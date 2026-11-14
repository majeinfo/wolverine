package awss3

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"

	"wolverine/internal/source"
)

// fakeSQS is a queue: received messages leave it.
type fakeSQS struct {
	mu         sync.Mutex
	messages   []sqstypes.Message
	deleted    []string
	visibility map[string][]int32 // ChangeMessageVisibility calls, by receipt handle
	receiveErr error
}

func (q *fakeSQS) add(id, body string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.messages = append(q.messages, sqstypes.Message{MessageId: aws.String(id), ReceiptHandle: aws.String("rh-" + id), Body: aws.String(body)})
}

func (q *fakeSQS) GetQueueAttributes(context.Context, *sqs.GetQueueAttributesInput, ...func(*sqs.Options)) (*sqs.GetQueueAttributesOutput, error) {
	return &sqs.GetQueueAttributesOutput{Attributes: map[string]string{"ApproximateNumberOfMessages": "0"}}, nil
}

func (q *fakeSQS) ReceiveMessage(ctx context.Context, in *sqs.ReceiveMessageInput, _ ...func(*sqs.Options)) (*sqs.ReceiveMessageOutput, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.receiveErr != nil {
		return nil, q.receiveErr
	}
	if in.MaxNumberOfMessages != 1 {
		return nil, fmt.Errorf("MaxNumberOfMessages %d, want 1", in.MaxNumberOfMessages)
	}
	if len(q.messages) == 0 {
		return &sqs.ReceiveMessageOutput{}, ctx.Err()
	}
	m := q.messages[0]
	q.messages = q.messages[1:]
	return &sqs.ReceiveMessageOutput{Messages: []sqstypes.Message{m}}, nil
}

func (q *fakeSQS) DeleteMessage(_ context.Context, in *sqs.DeleteMessageInput, _ ...func(*sqs.Options)) (*sqs.DeleteMessageOutput, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.deleted = append(q.deleted, aws.ToString(in.ReceiptHandle))
	return &sqs.DeleteMessageOutput{}, nil
}

func (q *fakeSQS) ChangeMessageVisibility(_ context.Context, in *sqs.ChangeMessageVisibilityInput, _ ...func(*sqs.Options)) (*sqs.ChangeMessageVisibilityOutput, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.visibility == nil {
		q.visibility = map[string][]int32{}
	}
	h := aws.ToString(in.ReceiptHandle)
	q.visibility[h] = append(q.visibility[h], in.VisibilityTimeout)
	return &sqs.ChangeMessageVisibilityOutput{}, nil
}

// fakeS3 holds objects by "bucket/key"; a nil content is an access error.
type fakeS3 map[string][]byte

func (b fakeS3) GetObject(_ context.Context, in *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	content, ok := b[aws.ToString(in.Bucket)+"/"+aws.ToString(in.Key)]
	switch {
	case !ok:
		return nil, &s3types.NoSuchKey{}
	case content == nil:
		return nil, errors.New("AccessDenied")
	}
	return &s3.GetObjectOutput{Body: io.NopCloser(bytes.NewReader(content))}, nil
}

func gz(s string) []byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write([]byte(s))
	w.Close()
	return b.Bytes()
}

// "b1\nb2\n", compressed with bzip2.
var bz2, _ = hex.DecodeString("425a6839314159265359365d16290000024900001030001000200030cd3418c80c67177245385090365d1629")

func s3Event(bucket string, keys ...string) string {
	var records []string
	for _, k := range keys {
		records = append(records, fmt.Sprintf(`{"eventSource":"aws:s3","eventName":"ObjectCreated:Put","s3":{"bucket":{"name":%q},"object":{"key":%q,"size":1}}}`, bucket, k))
	}
	return `{"Records":[` + strings.Join(records, ",") + `]}`
}

// read reads the source to its end. It returns the lines (as "file: line")
// and calls the Done functions in order, recording where they came.
func read(t *testing.T, s *Source) []string {
	t.Helper()
	if err := s.Open(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var out []string
	for {
		rec, err := s.Read(context.Background())
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		switch {
		case rec.Data != nil:
			out = append(out, rec.Fields["file"]+": "+string(rec.Data))
		case rec.Done != nil:
			rec.Done()
			out = append(out, "done")
		default:
			t.Fatalf("unexpected record %+v", rec)
		}
	}
}

func check(t *testing.T, got []string, want ...string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

func TestReadObjects(t *testing.T) {
	q := &fakeSQS{}
	q.add("m1", s3Event("logs", "alb/a.log.gz"))
	q.add("m2", s3Event("logs", "b.log.bz2", "c.log"))
	objects := fakeS3{
		"logs/alb/a.log.gz": gz("a1\r\na2\na3 no newline"),
		"logs/b.log.bz2":    bz2,
		"logs/c.log":        []byte("c1\n\nc3\n"),
	}
	s := &Source{ID: "s3", QueueURL: "https://sqs.eu-west-3.amazonaws.com/1/q", SQS: q, S3: objects}
	check(t, read(t, s),
		"s3://logs/alb/a.log.gz: a1", "s3://logs/alb/a.log.gz: a2", "s3://logs/alb/a.log.gz: a3 no newline", "done",
		"s3://logs/b.log.bz2: b1", "s3://logs/b.log.bz2: b2",
		"s3://logs/c.log: c1", "s3://logs/c.log: ", "s3://logs/c.log: c3", "done")
	check(t, q.deleted, "rh-m1", "rh-m2")
}

// A message is only deleted by its Done, i.e. once its lines have been
// processed.
func TestDeletedOnlyWhenDone(t *testing.T) {
	q := &fakeSQS{}
	q.add("m1", s3Event("logs", "a.log"))
	s := &Source{ID: "s3", SQS: q, S3: fakeS3{"logs/a.log": []byte("a1\n")}}
	s.Open(context.Background())
	rec, _ := s.Read(context.Background())
	if string(rec.Data) != "a1" || len(q.deleted) != 0 {
		t.Fatalf("got %+v, deleted %v", rec, q.deleted)
	}
	rec, _ = s.Read(context.Background())
	if rec.Data != nil || rec.Done == nil || len(q.deleted) != 0 {
		t.Fatalf("got %+v, deleted %v", rec, q.deleted)
	}
	s.Close() // the Done may come after Close: the engine is still processing
	rec.Done()
	check(t, q.deleted, "rh-m1")
}

// The first lines of every object are skipped (a header), gzipped ones
// included.
func TestSkipLines(t *testing.T) {
	q := &fakeSQS{}
	q.add("m1", s3Event("logs", "a.log.gz", "short.log"))
	q.add("m2", s3Event("logs", "b.log"))
	objects := fakeS3{
		"logs/a.log.gz":  gz("#Version: 1.0\n#Fields: date time\na1\na2\n"),
		"logs/short.log": []byte("#Version: 1.0\n"),
		"logs/b.log":     []byte("#Version: 1.0\n#Fields: date time\nb1"),
	}
	s := &Source{ID: "s3", SQS: q, S3: objects, SkipLines: 2}
	check(t, read(t, s), "s3://logs/a.log.gz: a1", "s3://logs/a.log.gz: a2", "done", "s3://logs/b.log: b1", "done")
	check(t, q.deleted, "rh-m1", "rh-m2")
}

func TestKeyRegexp(t *testing.T) {
	q := &fakeSQS{}
	q.add("m1", s3Event("logs", "a.log", "a.json"))
	s := &Source{ID: "s3", SQS: q, S3: fakeS3{"logs/a.log": []byte("a\n")}, KeyRegexp: regexp.MustCompile(`\.log$`)}
	check(t, read(t, s), "s3://logs/a.log: a", "done")
	check(t, q.deleted, "rh-m1")
}

func TestObjectErrors(t *testing.T) {
	q := &fakeSQS{}
	q.add("gone", s3Event("logs", "gone.log"))
	q.add("denied", s3Event("logs", "denied.log"))
	q.add("garbage", `not json`)
	q.add("ok", s3Event("logs", "ok.log"))
	s := &Source{ID: "s3", SQS: q, S3: fakeS3{"logs/denied.log": nil, "logs/ok.log": []byte("ok\n")}}
	check(t, read(t, s), "done", "s3://logs/ok.log: ok", "done")
	// A deleted object is skipped; the others are left in the queue, to be
	// read again later (or moved to the dead-letter queue).
	check(t, q.deleted, "rh-gone", "rh-ok")
}

func TestTestEvent(t *testing.T) {
	q := &fakeSQS{}
	q.add("m1", `{"Service":"Amazon S3","Event":"s3:TestEvent","Time":"2026-11-10T10:00:00.000Z","Bucket":"logs"}`)
	s := &Source{ID: "s3", SQS: q, S3: fakeS3{}}
	check(t, read(t, s), "done")
	check(t, q.deleted, "rh-m1")
}

// Close during an object releases its message: it is read again by the
// next run instead of waiting for the visibility timeout.
func TestCloseReleases(t *testing.T) {
	q := &fakeSQS{}
	q.add("m1", s3Event("logs", "a.log"))
	s := &Source{ID: "s3", SQS: q, S3: fakeS3{"logs/a.log": []byte("a1\na2\n")}}
	s.Open(context.Background())
	s.Read(context.Background())
	s.Close()
	if v := q.visibility["rh-m1"]; !slices.Equal(v, []int32{0}) || len(q.deleted) != 0 {
		t.Errorf("visibility calls %v, deleted %v", v, q.deleted)
	}
}

// The visibility of a message is extended while its object is read.
func TestExtendVisibility(t *testing.T) {
	q := &fakeSQS{}
	q.add("m1", s3Event("logs", "a.log"))
	s := &Source{ID: "s3", SQS: q, S3: fakeS3{"logs/a.log": []byte("a1\na2\na3\n")}, VisibilityTimeout: 20 * time.Second}
	s.Open(context.Background())
	defer s.Close()
	s.Read(context.Background())
	s.msg.extended = time.Now().Add(-11 * time.Second) // more than half elapsed
	s.Read(context.Background())
	s.Read(context.Background())
	if v := q.visibility["rh-m1"]; !slices.Equal(v, []int32{20}) {
		t.Errorf("visibility calls %v, want one extension to 20s", v)
	}
}

func TestFollow(t *testing.T) {
	q := &fakeSQS{}
	s := &Source{ID: "s3", SQS: q, S3: fakeS3{"logs/a.log": []byte("a1\n")}, Follow: true}
	s.Open(context.Background())
	defer s.Close()
	go func() {
		time.Sleep(50 * time.Millisecond)
		q.add("m1", s3Event("logs", "a.log"))
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rec, err := s.Read(ctx) // keeps polling the empty queue
	if err != nil || string(rec.Data) != "a1" {
		t.Fatalf("got %+v, %v", rec, err)
	}
	s.Read(ctx) // done
	cancel()
	if _, err := s.Read(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("after cancel: %v", err)
	}
}

func TestReceiveError(t *testing.T) {
	q := &fakeSQS{receiveErr: errors.New("AccessDenied")}
	s := &Source{ID: "s3", QueueURL: "https://sqs.eu-west-3.amazonaws.com/1/q", SQS: q, S3: fakeS3{}}
	s.Open(context.Background())
	if _, err := s.Read(context.Background()); err == nil || !strings.Contains(err.Error(), "AccessDenied") {
		t.Fatalf("got %v", err)
	}
}

func TestParseNotification(t *testing.T) {
	tests := []struct {
		name, body string
		want       []object
		err        bool
	}{
		{"S3 event with an encoded key", s3Event("logs", "AWSLogs/my+file%3D1.log.gz"), []object{{"logs", "AWSLogs/my file=1.log.gz"}}, false},
		{"deletion", `{"Records":[{"eventSource":"aws:s3","eventName":"ObjectRemoved:Delete","s3":{"bucket":{"name":"logs"},"object":{"key":"a"}}}]}`, nil, false},
		{"test event", `{"Service":"Amazon S3","Event":"s3:TestEvent"}`, nil, false},
		{"through SNS", fmt.Sprintf(`{"Type":"Notification","MessageId":"x","Message":%q}`, s3Event("logs", "a.log")), []object{{"logs", "a.log"}}, false},
		{"EventBridge", `{"source":"aws.s3","detail-type":"Object Created","detail":{"bucket":{"name":"logs"},"object":{"key":"my file.log"}}}`, []object{{"logs", "my file.log"}}, false},
		{"EventBridge deletion", `{"source":"aws.s3","detail-type":"Object Deleted","detail":{"bucket":{"name":"logs"},"object":{"key":"a"}}}`, nil, false},
		{"not JSON", `hello`, nil, true},
		{"other JSON", `{"hello":"world"}`, nil, true},
		{"bad encoding", s3Event("logs", "%zz"), nil, true},
	}
	for _, tt := range tests {
		got, err := parseNotification(tt.body)
		if (err != nil) != tt.err || !slices.Equal(got, tt.want) {
			t.Errorf("%s: got %v, %v; want %v (error: %v)", tt.name, got, err, tt.want, tt.err)
		}
	}
}

// The source only needs these to implement source.Source.
var _ source.Source = (*Source)(nil)
