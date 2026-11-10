// Package awss3 implements the "aws-s3" source: log files written to an S3
// bucket, announced by the bucket's notifications in an SQS queue.
//
// For each notification of a created object, the object is downloaded,
// decompressed if needed (gzip, bzip2) and read line by line. The SQS
// message is deleted once every line has been processed (source.Record's
// Done): if wolverine stops or fails before, the message becomes visible
// again and the file is read again by the next run. Reading is therefore
// at least once.
package awss3

import (
	"bufio"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"

	"wolverine/internal/source"
	"wolverine/internal/verbose"
)

const (
	defaultVisibility = 5 * time.Minute
	// defaultWait is the long polling wait of SQS (its maximum). When not
	// following, a shorter wait is used: an empty answer ends the reading.
	defaultWait  = 20 * time.Second
	oneShotWait  = 2 * time.Second
	maxBackoff   = time.Minute
	callTimeout  = 30 * time.Second
	readerBuffer = 64 * 1024
)

// SQSAPI is the part of the SQS client the source uses.
type SQSAPI interface {
	GetQueueAttributes(context.Context, *sqs.GetQueueAttributesInput, ...func(*sqs.Options)) (*sqs.GetQueueAttributesOutput, error)
	ReceiveMessage(context.Context, *sqs.ReceiveMessageInput, ...func(*sqs.Options)) (*sqs.ReceiveMessageOutput, error)
	DeleteMessage(context.Context, *sqs.DeleteMessageInput, ...func(*sqs.Options)) (*sqs.DeleteMessageOutput, error)
	ChangeMessageVisibility(context.Context, *sqs.ChangeMessageVisibilityInput, ...func(*sqs.Options)) (*sqs.ChangeMessageVisibilityOutput, error)
}

// S3API is the part of the S3 client the source uses.
type S3API interface {
	GetObject(context.Context, *s3.GetObjectInput, ...func(*s3.Options)) (*s3.GetObjectOutput, error)
}

// Source reads the objects announced in an SQS queue. It implements
// source.Source.
//
// Messages are received one at a time. While an object is being read, the
// visibility timeout of its message is extended, so that a long download
// is not given to another receiver.
//
// When Follow is not set, Read returns io.EOF once the queue is empty.
type Source struct {
	ID        string
	QueueURL  string
	KeyRegexp *regexp.Regexp // nil: every object
	Follow    bool
	// VisibilityTimeout of the messages being read (default: 5m).
	VisibilityTimeout time.Duration
	// WaitTime of the long polling (default: 20s when following, 2s
	// otherwise).
	WaitTime time.Duration
	SQS      SQSAPI
	S3       S3API

	msg      *message // being read
	failures int      // consecutive failures, for the backoff
}

// object is an S3 object announced by a notification.
type object struct{ bucket, key string }

func (o object) String() string { return "s3://" + o.bucket + "/" + o.key }

// message is the SQS message being read.
type message struct {
	id, handle string
	objects    []object // not read yet
	file       string   // the object being read
	body       io.Closer
	r          *bufio.Reader
	extended   time.Time // when its visibility was last set
}

func (s *Source) Name() string { return s.ID }

func (s *Source) visibility() time.Duration {
	if s.VisibilityTimeout > 0 {
		return s.VisibilityTimeout
	}
	return defaultVisibility
}

// Open checks that the queue can be reached with the credentials.
func (s *Source) Open(ctx context.Context) error {
	out, err := s.SQS.GetQueueAttributes(ctx, &sqs.GetQueueAttributesInput{
		QueueUrl:       aws.String(s.QueueURL),
		AttributeNames: []sqstypes.QueueAttributeName{sqstypes.QueueAttributeNameApproximateNumberOfMessages},
	})
	if err != nil {
		return fmt.Errorf("queue %s: %w", s.QueueURL, err)
	}
	verbose.Infof("source %s: queue %s: about %s messages waiting", s.ID, s.QueueURL,
		out.Attributes[string(sqstypes.QueueAttributeNameApproximateNumberOfMessages)])
	return nil
}

// Close stops reading. The message being read, if any, is made visible
// again right away, so that the next run reads its object again.
func (s *Source) Close() error {
	m := s.msg
	if m == nil {
		return nil
	}
	s.msg = nil
	if m.body != nil {
		m.body.Close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	_, err := s.SQS.ChangeMessageVisibility(ctx, &sqs.ChangeMessageVisibilityInput{
		QueueUrl: aws.String(s.QueueURL), ReceiptHandle: aws.String(m.handle), VisibilityTimeout: 0,
	})
	verbose.Debugf("source %s: message %s released, its object will be read again", s.ID, m.id)
	return err
}

// Read returns the next line of the objects announced in the queue. After
// the last line of a message's objects, it returns a record without data
// whose Done deletes the message.
func (s *Source) Read(ctx context.Context) (*source.Record, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if m := s.msg; m != nil {
			rec, err := s.readMessage(ctx, m)
			if rec != nil || err != nil {
				return rec, err
			}
			continue
		}

		msg, err := s.receive(ctx)
		if err != nil {
			if ctx.Err() != nil || !s.Follow {
				return nil, err
			}
			log.Printf("source %s: %v", s.ID, err)
			s.backoff(ctx)
			continue
		}
		s.failures = 0
		if msg == nil {
			if !s.Follow {
				return nil, io.EOF
			}
			continue
		}
		s.start(msg)
	}
}

// receive waits for one message (nil if none came).
func (s *Source) receive(ctx context.Context) (*sqstypes.Message, error) {
	wait := s.WaitTime
	if wait <= 0 {
		wait = defaultWait
		if !s.Follow {
			wait = oneShotWait
		}
	}
	out, err := s.SQS.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{
		QueueUrl:            aws.String(s.QueueURL),
		MaxNumberOfMessages: 1,
		WaitTimeSeconds:     int32(wait / time.Second),
		VisibilityTimeout:   int32(s.visibility() / time.Second),
	})
	if err != nil {
		return nil, fmt.Errorf("receiving from %s: %w", s.QueueURL, err)
	}
	if len(out.Messages) == 0 {
		return nil, nil
	}
	return &out.Messages[0], nil
}

// start makes msg the message being read.
func (s *Source) start(msg *sqstypes.Message) {
	m := &message{id: aws.ToString(msg.MessageId), handle: aws.ToString(msg.ReceiptHandle), extended: time.Now()}
	objects, err := parseNotification(aws.ToString(msg.Body))
	if err != nil {
		// Left in the queue: it comes back after the visibility timeout,
		// and goes to the dead-letter queue if the queue has one.
		log.Printf("source %s: message %s is not an S3 notification, left in the queue: %v: %.200q", s.ID, m.id, err, aws.ToString(msg.Body))
		return
	}
	for _, o := range objects {
		if s.KeyRegexp != nil && !s.KeyRegexp.MatchString(o.key) {
			verbose.Debugf("source %s: %s skipped: its key does not match key_regexp", s.ID, o)
			continue
		}
		m.objects = append(m.objects, o)
	}
	if len(objects) == 0 {
		verbose.Debugf("source %s: message %s announces no new object (test event, deletion...): deleted", s.ID, m.id)
	}
	s.msg = m
}

// readMessage returns the next record of the message being read: a line,
// or, at the end, the record that deletes the message. It returns nil when
// it moved on to another object (or gave up the message).
func (s *Source) readMessage(ctx context.Context, m *message) (*source.Record, error) {
	if m.r == nil {
		if len(m.objects) == 0 {
			s.msg = nil
			return &source.Record{Source: s.ID, Done: s.deleter(m)}, nil
		}
		o := m.objects[0]
		m.objects = m.objects[1:]
		err := s.openObject(ctx, m, o)
		var noKey *s3types.NoSuchKey
		switch {
		case err == nil:
			verbose.Infof("source %s: reading %s", s.ID, o)
		case ctx.Err() != nil:
			return nil, ctx.Err()
		case errors.As(err, &noKey):
			log.Printf("source %s: %s no longer exists, skipped", s.ID, o)
		default:
			s.giveUp(m, fmt.Errorf("%s: %w", o, err))
		}
		return nil, nil
	}

	if err := s.extend(ctx, m); err != nil {
		log.Printf("source %s: extending the visibility of message %s: %v", s.ID, m.id, err)
	}
	line, err := m.r.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		s.giveUp(m, fmt.Errorf("%s: %w", m.file, err))
		return nil, nil
	}
	if err != nil { // end of the object
		m.body.Close()
		m.body, m.r = nil, nil
		if line == "" {
			return nil, nil
		}
	}
	return &source.Record{
		Data:      []byte(strings.TrimRight(line, "\r\n")),
		Timestamp: time.Now(),
		Source:    s.ID,
		Fields:    map[string]string{"file": m.file},
	}, nil
}

// openObject starts downloading an object.
func (s *Source) openObject(ctx context.Context, m *message, o object) error {
	out, err := s.S3.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(o.bucket), Key: aws.String(o.key)})
	if err != nil {
		return err
	}
	r, err := decompress(out.Body)
	if err != nil {
		out.Body.Close()
		return err
	}
	m.file, m.body, m.r = o.String(), out.Body, bufio.NewReaderSize(r, readerBuffer)
	return nil
}

// giveUp stops reading a message after an error. It is not deleted: it
// comes back after its visibility timeout, and its objects are read again.
func (s *Source) giveUp(m *message, err error) {
	log.Printf("source %s: %v; message %s will be read again later", s.ID, err, m.id)
	if m.body != nil {
		m.body.Close()
	}
	s.msg = nil
}

// extend pushes back the visibility timeout of the message being read,
// when half of it has elapsed.
func (s *Source) extend(ctx context.Context, m *message) error {
	if time.Since(m.extended) < s.visibility()/2 {
		return nil
	}
	m.extended = time.Now()
	_, err := s.SQS.ChangeMessageVisibility(ctx, &sqs.ChangeMessageVisibilityInput{
		QueueUrl: aws.String(s.QueueURL), ReceiptHandle: aws.String(m.handle),
		VisibilityTimeout: int32(s.visibility() / time.Second),
	})
	verbose.Debugf("source %s: visibility of message %s extended", s.ID, m.id)
	return err
}

// deleter returns the function that deletes a message once its lines have
// been processed. It runs in the engine, possibly after Close.
func (s *Source) deleter(m *message) func() {
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
		defer cancel()
		_, err := s.SQS.DeleteMessage(ctx, &sqs.DeleteMessageInput{QueueUrl: aws.String(s.QueueURL), ReceiptHandle: aws.String(m.handle)})
		if err != nil {
			log.Printf("source %s: deleting message %s: %v (its objects will be read again)", s.ID, m.id, err)
			return
		}
		verbose.Debugf("source %s: message %s deleted", s.ID, m.id)
	}
}

// backoff waits after a failure, longer and longer, up to maxBackoff.
func (s *Source) backoff(ctx context.Context) {
	s.failures++
	d := min(time.Second<<min(s.failures-1, 6), maxBackoff)
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}

// decompress returns the uncompressed content of r: gzip and bzip2 are
// recognized by their first bytes, anything else is read as is.
func decompress(r io.Reader) (io.Reader, error) {
	br := bufio.NewReaderSize(r, readerBuffer)
	magic, _ := br.Peek(3)
	switch {
	case len(magic) >= 2 && magic[0] == 0x1f && magic[1] == 0x8b:
		return gzip.NewReader(br)
	case len(magic) == 3 && string(magic) == "BZh":
		return bzip2.NewReader(br), nil
	}
	return br, nil
}

// parseNotification returns the objects created according to an SQS
// message body: an S3 event notification, the same wrapped by SNS, or an
// EventBridge event. S3's test event and the other events (deletions...)
// give no object.
func parseNotification(body string) ([]object, error) {
	var n struct {
		// S3 event notification.
		Records []struct {
			EventSource string `json:"eventSource"`
			EventName   string `json:"eventName"`
			S3          struct {
				Bucket struct {
					Name string `json:"name"`
				} `json:"bucket"`
				Object struct {
					Key string `json:"key"`
				} `json:"object"`
			} `json:"s3"`
		} `json:"Records"`
		// S3 test event.
		Event string `json:"Event"`
		// SNS notification.
		Type    string `json:"Type"`
		Message string `json:"Message"`
		// EventBridge event.
		Source     string `json:"source"`
		DetailType string `json:"detail-type"`
		Detail     struct {
			Bucket struct {
				Name string `json:"name"`
			} `json:"bucket"`
			Object struct {
				Key string `json:"key"`
			} `json:"object"`
		} `json:"detail"`
	}
	if err := json.Unmarshal([]byte(body), &n); err != nil {
		return nil, err
	}
	switch {
	case n.Type == "Notification" && n.Message != "":
		return parseNotification(n.Message)
	case n.Event == "s3:TestEvent":
		return nil, nil
	case n.Source == "aws.s3":
		if n.DetailType != "Object Created" {
			return nil, nil
		}
		if n.Detail.Bucket.Name == "" || n.Detail.Object.Key == "" {
			return nil, errors.New("EventBridge event without bucket or key")
		}
		return []object{{n.Detail.Bucket.Name, n.Detail.Object.Key}}, nil
	case n.Records != nil:
		var objects []object
		for _, r := range n.Records {
			if r.EventSource != "aws:s3" || !strings.HasPrefix(r.EventName, "ObjectCreated:") {
				continue
			}
			// The keys of S3 notifications are URL-encoded ("+" for spaces).
			key, err := url.QueryUnescape(r.S3.Object.Key)
			if err != nil {
				return nil, fmt.Errorf("key %q: %w", r.S3.Object.Key, err)
			}
			if r.S3.Bucket.Name == "" || key == "" {
				return nil, errors.New("S3 record without bucket or key")
			}
			objects = append(objects, object{r.S3.Bucket.Name, key})
		}
		return objects, nil
	}
	return nil, errors.New("unknown message format")
}
