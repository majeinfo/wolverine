package awss3

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"wolverine/internal/config"
)

const queueURL = "https://sqs.eu-west-3.amazonaws.com/123456789012/logs"

// isolate hides the AWS settings of the machine running the tests.
func isolate(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, v := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_REGION", "AWS_DEFAULT_REGION", "AWS_PROFILE", "AWS_ENDPOINT_URL"} {
		t.Setenv(v, "")
	}
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(dir, "none"))
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(dir, "none"))
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	return dir
}

func keysOf(t *testing.T, c *Clients) string {
	t.Helper()
	creds, err := c.SQS.Options().Credentials.Retrieve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return creds.AccessKeyID + ":" + creds.SecretAccessKey + ":" + creds.SessionToken
}

func TestClientsKeysFromEnvironment(t *testing.T) {
	isolate(t)
	t.Setenv("SRC1_KEY", "AKIA1")
	t.Setenv("SRC1_SECRET", "secret1")
	t.Setenv("SRC1_TOKEN", "token1")
	// The machine's default keys must not be used instead.
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIADEFAULT")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "default")
	c, err := NewClients(context.Background(), config.AWS{AccessKeyIDEnv: "SRC1_KEY", SecretAccessKeyEnv: "SRC1_SECRET", SessionTokenEnv: "SRC1_TOKEN"}, queueURL)
	if err != nil {
		t.Fatal(err)
	}
	if got := keysOf(t, c); got != "AKIA1:secret1:token1" {
		t.Errorf("credentials %s", got)
	}
	if c.Region != "eu-west-3" {
		t.Errorf("region %q, want the queue's", c.Region)
	}
}

func TestClientsDefaults(t *testing.T) {
	isolate(t)
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIADEFAULT")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "default")
	t.Setenv("AWS_REGION", "us-east-1")
	c, err := NewClients(context.Background(), config.AWS{}, queueURL)
	if err != nil {
		t.Fatal(err)
	}
	if got := keysOf(t, c); got != "AKIADEFAULT:default:" || c.Region != "us-east-1" {
		t.Errorf("credentials %s, region %s", got, c.Region)
	}
}

func TestClientsProfile(t *testing.T) {
	dir := isolate(t)
	creds := filepath.Join(dir, "credentials")
	conf := filepath.Join(dir, "config")
	os.WriteFile(creds, []byte("[default]\naws_access_key_id = AKIADEF\naws_secret_access_key = def\n\n[wolverine]\naws_access_key_id = AKIAWOLF\naws_secret_access_key = wolf\n"), 0o600)
	os.WriteFile(conf, []byte("[profile wolverine]\nregion = ap-southeast-2\n"), 0o600)

	c, err := NewClients(context.Background(), config.AWS{Profile: "wolverine", CredentialsFile: creds, ConfigFile: conf}, queueURL)
	if err != nil {
		t.Fatal(err)
	}
	if got := keysOf(t, c); got != "AKIAWOLF:wolf:" || c.Region != "ap-southeast-2" {
		t.Errorf("credentials %s, region %s", got, c.Region)
	}

	// The default profile of a given credentials file; aws.region wins.
	c, err = NewClients(context.Background(), config.AWS{CredentialsFile: creds, Region: "eu-central-1"}, queueURL)
	if err != nil {
		t.Fatal(err)
	}
	if got := keysOf(t, c); got != "AKIADEF:def:" || c.Region != "eu-central-1" {
		t.Errorf("credentials %s, region %s", got, c.Region)
	}
}

func TestClientsErrors(t *testing.T) {
	dir := isolate(t)
	t.Setenv("SET", "x")
	tests := []struct {
		name string
		aws  config.AWS
		url  string
		want string
	}{
		{"key without secret", config.AWS{AccessKeyIDEnv: "SET"}, queueURL, "go together"},
		{"unset variable", config.AWS{AccessKeyIDEnv: "SET", SecretAccessKeyEnv: "WOLVERINE_UNSET"}, queueURL, "WOLVERINE_UNSET is not set"},
		{"keys and profile", config.AWS{AccessKeyIDEnv: "SET", SecretAccessKeyEnv: "SET", Profile: "p"}, queueURL, "either keys"},
		{"missing credentials file", config.AWS{CredentialsFile: filepath.Join(dir, "nope")}, queueURL, "credentials_file"},
		{"unknown profile", config.AWS{Profile: "nope"}, queueURL, "nope"},
		{"no region", config.AWS{}, "https://localhost:4566/000000000000/q", "no region"},
	}
	for _, tt := range tests {
		if _, err := NewClients(context.Background(), tt.aws, tt.url); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: got %v, want an error containing %q", tt.name, err, tt.want)
		}
	}
}

func TestRegionFromQueueURL(t *testing.T) {
	for url, want := range map[string]string{
		"https://sqs.eu-west-3.amazonaws.com/123/q":           "eu-west-3",
		"https://sqs.cn-north-1.amazonaws.com.cn/123/q":       "cn-north-1",
		"https://us-west-2.queue.amazonaws.com/123/q":         "us-west-2",
		"https://localhost:4566/000000000000/q":               "",
		"http://sqs.us-east-1.localhost.localstack.cloud/1/q": "us-east-1",
	} {
		if got := regionFromQueueURL(url); got != want {
			t.Errorf("%s: got %q, want %q", url, got, want)
		}
	}
}
