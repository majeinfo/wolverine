package engine

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"

	"wolverine/internal/config"
	"wolverine/internal/event"
	"wolverine/internal/source/awss3"
)

// fakeAWS serves the SQS JSON protocol and S3 GetObject (path style).
type fakeAWS struct {
	mu       sync.Mutex
	queue    []string          // message bodies not received yet
	handles  map[string]string // receipt handle -> body, received and not deleted
	deleted  []string
	objects  map[string][]byte // by "/bucket/key"
	keyIDs   map[string]bool   // access key ids of the signed requests
	received int
}

// Credential=<key id>/<date>/<region>/<service>/aws4_request
var credentialRe = regexp.MustCompile(`Credential=([^/]+)/[0-9]+/([^/]+)/([^/]+)/`)

func (f *fakeAWS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if m := credentialRe.FindStringSubmatch(r.Header.Get("Authorization")); m != nil {
		f.keyIDs[m[1]+" "+m[2]+" "+m[3]] = true
	}

	op, isSQS := strings.CutPrefix(r.Header.Get("X-Amz-Target"), "AmazonSQS.")
	if !isSQS {
		content, ok := f.objects[r.URL.Path]
		if r.Method != http.MethodGet || !ok {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message></Error>`)
			return
		}
		w.Write(content)
		return
	}

	var in map[string]any
	json.NewDecoder(r.Body).Decode(&in)
	w.Header().Set("Content-Type", "application/x-amz-json-1.0")
	var out any = map[string]any{}
	switch op {
	case "GetQueueAttributes":
		out = map[string]any{"Attributes": map[string]string{"ApproximateNumberOfMessages": fmt.Sprint(len(f.queue))}}
	case "ReceiveMessage":
		if len(f.queue) > 0 {
			body := f.queue[0]
			f.queue = f.queue[1:]
			f.received++
			handle := fmt.Sprintf("handle-%d", f.received)
			f.handles[handle] = body
			sum := md5.Sum([]byte(body))
			out = map[string]any{"Messages": []map[string]string{{
				"MessageId": fmt.Sprintf("id-%d", f.received), "ReceiptHandle": handle,
				"Body": body, "MD5OfBody": hex.EncodeToString(sum[:]),
			}}}
		}
	case "DeleteMessage":
		h, _ := in["ReceiptHandle"].(string)
		delete(f.handles, h)
		f.deleted = append(f.deleted, h)
	case "ChangeMessageVisibility":
	default:
		w.WriteHeader(http.StatusBadRequest)
		out = map[string]string{"__type": "InvalidAction", "message": op}
	}
	json.NewEncoder(w).Encode(out)
}

func gzipped(s string) []byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write([]byte(s))
	w.Close()
	return b.Bytes()
}

func TestRunAWSS3(t *testing.T) {
	var lines strings.Builder
	for i := 1; i <= 4; i++ {
		fmt.Fprintf(&lines, "Nov 10 10:0%d:00 web1 sshd[%d]: Failed password for root from 198.51.100.4 port 4%d ssh2\n", i, i, i)
	}
	fake := &fakeAWS{
		handles: map[string]string{},
		keyIDs:  map[string]bool{},
		objects: map[string][]byte{
			"/logs/AWSLogs/web1/secure 1.gz": gzipped(lines.String()),
		},
		queue: []string{
			`{"Service":"Amazon S3","Event":"s3:TestEvent","Bucket":"logs"}`,
			`{"Records":[{"eventSource":"aws:s3","eventName":"ObjectCreated:Put","s3":{"bucket":{"name":"logs"},"object":{"key":"AWSLogs/web1/secure+1.gz"}}}]}`,
			`{"Records":[{"eventSource":"aws:s3","eventName":"ObjectCreated:Put","s3":{"bucket":{"name":"logs"},"object":{"key":"AWSLogs/web1/deleted-since.gz"}}}]}`,
		},
	}
	srv := httptest.NewServer(fake)
	defer srv.Close()

	t.Setenv("TEST_AWS_KEY", "AKIATESTSOURCE")
	t.Setenv("TEST_AWS_SECRET", "secret")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	cfg, err := config.Load("../../config/wolverine.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var messages config.Source
	for _, s := range cfg.Sources {
		if s.ID == "messages" {
			messages = s
		}
	}
	cfg.StateFile = ""
	cfg.LogTTL = oldLogs // logs of a fixed date
	cfg.Sources = []config.Source{{
		ID:       "s3-logs",
		Type:     "aws-s3",
		QueueURL: srv.URL + "/123456789012/logs",
		Regexp:   messages.Regexp, // syslog lines
		AWS: config.AWS{
			Region:             "eu-west-3",
			AccessKeyIDEnv:     "TEST_AWS_KEY",
			SecretAccessKeyEnv: "TEST_AWS_SECRET",
			EndpointURL:        srv.URL,
		},
	}}

	eng, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	eng.Alerts = &out
	eng.AlertEvents = AllAlertEvents
	if err := eng.Run(context.Background()); err != nil {
		t.Fatal(err)
	}

	// The shipped SSH rule (3 failures per IP) fired on the downloaded file.
	var a event.Alert
	if err := json.Unmarshal(out.Bytes(), &a); err != nil {
		t.Fatalf("%v: %s", err, out.String())
	}
	if a.RuleID != "ssh-failed-logins-per-ip" || a.Metadata["value"] != "198.51.100.4" {
		t.Errorf("unexpected alert: %+v", a)
	}
	if f := a.Events[0].Fields["file"]; f != "s3://logs/AWSLogs/web1/secure 1.gz" {
		t.Errorf("file field %q", f)
	}
	if n := eng.inputs[0].lines.Load(); n != 4 {
		t.Errorf("%d lines, want 4", n)
	}

	// Every message was deleted once processed, including the test event
	// and the notification of an object deleted since.
	if len(fake.deleted) != 3 || len(fake.handles) != 0 {
		t.Errorf("deleted %v, still in flight %v", fake.deleted, fake.handles)
	}
	// The requests were signed with the source's keys, for its region.
	if len(fake.keyIDs) != 2 || !fake.keyIDs["AKIATESTSOURCE eu-west-3 sqs"] || !fake.keyIDs["AKIATESTSOURCE eu-west-3 s3"] {
		t.Errorf("signed with %v", fake.keyIDs)
	}
}

func TestBuildAWSS3Errors(t *testing.T) {
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	ok := config.Source{ID: "s3", Type: "aws-s3", QueueURL: "https://sqs.eu-west-3.amazonaws.com/1/q", Regexp: `^(?P<message>.*)$`}
	tests := []struct {
		name string
		mod  func(*config.Source)
		want string
	}{
		{"no queue", func(c *config.Source) { c.QueueURL = "" }, "queue_url is required"},
		{"bad queue", func(c *config.Source) { c.QueueURL = "sqs/q" }, "https:// URL"},
		{"no regexp", func(c *config.Source) { c.Regexp = "" }, "regexp is required"},
		{"bad key_regexp", func(c *config.Source) { c.KeyRegexp = "(" }, "key_regexp"},
		{"start_at", func(c *config.Source) { c.StartAt = "end" }, "start_at does not apply"},
		{"path", func(c *config.Source) { c.Path = "/x" }, "do not apply to an aws-s3 source"},
		{"visibility", func(c *config.Source) { c.VisibilityTimeout = 13 * 3600e9 }, "visibility_timeout"},
		{"short visibility", func(c *config.Source) { c.VisibilityTimeout = 1e9 }, "at least 10s"},
		{"missing key variable", func(c *config.Source) {
			c.AWS = config.AWS{AccessKeyIDEnv: "WOLVERINE_TEST_UNSET", SecretAccessKeyEnv: "WOLVERINE_TEST_UNSET"}
		}, "is not set"},
	}
	for _, tt := range tests {
		c := ok
		tt.mod(&c)
		if _, err := buildSources([]config.Source{c}); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: got %v, want an error containing %q", tt.name, err, tt.want)
		}
	}

	// The aws-s3 settings are rejected on other sources.
	c := logfile("/var/log/messages")
	c.QueueURL = ok.QueueURL
	if _, err := buildSources([]config.Source{c}); err == nil || !strings.Contains(err.Error(), "only apply to an aws-s3 source") {
		t.Errorf("logfile with queue_url: got %v", err)
	}

	in, err := buildSources([]config.Source{ok})
	if err != nil {
		t.Fatal(err)
	}
	if s := in[0].source.(*awss3.Source); s.QueueURL != ok.QueueURL {
		t.Errorf("unexpected source %+v", s)
	}
}
