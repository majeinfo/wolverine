package action

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"wolverine/internal/action/awswaf"
	"wolverine/internal/action/file"
	"wolverine/internal/action/webhook"
	"wolverine/internal/config"
	"wolverine/internal/event"
)

func emailCfg() config.Action {
	return config.Action{
		ID: "mail", Type: "email",
		SMTP: config.SMTP{Host: "localhost"},
		From: "w@example.com", To: []string{"a@example.com"},
	}
}

func TestBuildErrors(t *testing.T) {
	tests := []struct {
		name string
		mod  func(*config.Action)
		want string
	}{
		{"missing id", func(c *config.Action) { c.ID = "" }, "missing id"},
		{"unknown type", func(c *config.Action) { c.Type = "sms" }, "unknown type"},
		{"no host", func(c *config.Action) { c.SMTP.Host = "" }, "smtp.host"},
		{"bad from", func(c *config.Action) { c.From = "nope" }, "from"},
		{"no to", func(c *config.Action) { c.To = nil }, "recipient"},
		{"bad to", func(c *config.Action) { c.To = []string{"nope"} }, "to"},
		{"unset password env", func(c *config.Action) { c.SMTP.PasswordEnv = "WOLVERINE_TEST_UNSET_VAR" }, "WOLVERINE_TEST_UNSET_VAR"},
	}
	for _, tt := range tests {
		c := emailCfg()
		tt.mod(&c)
		if _, err := Build([]config.Action{c}); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: got error %v, want it to contain %q", tt.name, err, tt.want)
		}
	}
	if _, err := Build([]config.Action{emailCfg(), emailCfg()}); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("duplicate ids: got %v", err)
	}
}

func sshCfg() config.Action {
	return config.Action{
		ID: "block", Type: "ssh",
		SSH:     config.SSH{Host: "fw.example.com"},
		Command: "ipset add blocklist {{.SourceIP}} -exist",
	}
}

func TestBuildSSH(t *testing.T) {
	actions, err := Build([]config.Action{sshCfg()})
	if err != nil {
		t.Fatal(err)
	}
	if actions["block"] == nil || actions["block"].Name() != "block" {
		t.Errorf("unexpected actions: %v", actions)
	}

	tests := []struct {
		name string
		mod  func(*config.Action)
		want string
	}{
		{"no host", func(c *config.Action) { c.SSH.Host = "" }, "ssh.host"},
		{"option as host", func(c *config.Action) { c.SSH.Host = "-oProxyCommand=x" }, "invalid host"},
		{"no command", func(c *config.Action) { c.Command = "" }, "command is required"},
		{"bad template", func(c *config.Action) { c.Command = "echo {{.SourceIP" }, "command"},
		{"unknown variable", func(c *config.Action) { c.Command = "echo {{.Password}}" }, "available: AlertID"},
		{"missing key file", func(c *config.Action) { c.SSH.IdentityFile = "/nonexistent/key" }, "identity_file"},
	}
	for _, tt := range tests {
		c := sshCfg()
		tt.mod(&c)
		if _, err := Build([]config.Action{c}); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: got error %v, want it to contain %q", tt.name, err, tt.want)
		}
	}
}

func webhookCfg() config.Action {
	return config.Action{
		ID: "hook", Type: "webhook",
		Webhook: config.Webhook{URL: "https://hooks.example.com/wolverine"},
	}
}

func TestBuildWebhook(t *testing.T) {
	t.Setenv("WOLVERINE_TEST_TOKEN", "Bearer s3cret")
	c := webhookCfg()
	c.Webhook.Headers = map[string]string{"X-Source": "wolverine"}
	c.Webhook.HeadersEnv = map[string]string{"Authorization": "WOLVERINE_TEST_TOKEN"}
	actions, err := Build([]config.Action{c})
	if err != nil {
		t.Fatal(err)
	}
	w := actions["hook"].(*webhook.Webhook)
	if w.Headers["Authorization"] != "Bearer s3cret" || w.Headers["X-Source"] != "wolverine" {
		t.Errorf("unexpected webhook: %+v", w)
	}

	// The URL can come from the environment, and is never printed.
	t.Setenv("WOLVERINE_TEST_URL", "https://hooks.slack.com/services/T000/B000/SECRET")
	c = webhookCfg()
	c.Webhook.URL, c.Webhook.URLEnv = "", "WOLVERINE_TEST_URL"
	c.Webhook.Body, c.Webhook.Escape = `{"text": "{{.Message}}"}`, "slack"
	actions, err = Build([]config.Action{c})
	if err != nil {
		t.Fatal(err)
	}
	if w := actions["hook"].(*webhook.Webhook); w.URL != "https://hooks.slack.com/services/T000/B000/SECRET" || w.Body == nil {
		t.Errorf("unexpected webhook: %+v", w)
	}
	t.Setenv("WOLVERINE_TEST_URL", "ftp://hooks.slack.com/services/T000/B000/SECRET")
	if _, err := Build([]config.Action{c}); err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Errorf("an invalid url_env must fail without printing the URL: %v", err)
	}

	tests := []struct {
		name string
		mod  func(*config.Action)
		want string
	}{
		{"no url", func(c *config.Action) { c.Webhook.URL = "" }, "http:// or https://"},
		{"url and url_env", func(c *config.Action) { c.Webhook.URLEnv = "X" }, "not both"},
		{"unset url_env", func(c *config.Action) { c.Webhook.URL, c.Webhook.URLEnv = "", "WOLVERINE_TEST_UNSET_VAR" }, "WOLVERINE_TEST_UNSET_VAR"},
		{"bad body", func(c *config.Action) { c.Webhook.Body = `{"text": {{.SourceIP}}}` }, "not valid JSON"},
		{"unknown variable", func(c *config.Action) { c.Webhook.Body = `{"text": "{{.Password}}"}` }, "available:"},
		{"bad escape", func(c *config.Action) { c.Webhook.Body, c.Webhook.Escape = `{}`, "xml" }, "unknown escape"},
		{"escape without body", func(c *config.Action) { c.Webhook.Escape = "slack" }, "only used with"},
		{"bad scheme", func(c *config.Action) { c.Webhook.URL = "ftp://example.com" }, "http:// or https://"},
		{"negative retries", func(c *config.Action) { c.Webhook.Retries = -1 }, "retries"},
		{"unset env", func(c *config.Action) {
			c.Webhook.HeadersEnv = map[string]string{"Authorization": "WOLVERINE_TEST_UNSET_VAR"}
		}, "WOLVERINE_TEST_UNSET_VAR"},
		{"bad header name", func(c *config.Action) { c.Webhook.Headers = map[string]string{"X Bad": "v"} }, "invalid header"},
		{"header injection", func(c *config.Action) { c.Webhook.Headers = map[string]string{"X-A": "v\r\nX-B: w"} }, "invalid header"},
	}
	for _, tt := range tests {
		c := webhookCfg()
		tt.mod(&c)
		if _, err := Build([]config.Action{c}); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: got error %v, want it to contain %q", tt.name, err, tt.want)
		}
	}
}

func TestRoutes(t *testing.T) {
	disabled := emailCfg()
	disabled.ID, disabled.Disabled = "off", true
	actions, err := Build([]config.Action{emailCfg(), disabled})
	if err != nil {
		t.Fatal(err)
	}

	routes, err := Routes([]config.Rule{
		{ID: "r1", Actions: []string{"mail", "off"}},
		{ID: "r2", Actions: []string{"off"}},
		{ID: "r3", Actions: []string{"unknown"}, Disabled: true},
	}, actions)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes["r1"]) != 1 || routes["r1"][0].Name() != "mail" || len(routes["r2"]) != 0 {
		t.Errorf("unexpected routes: %v", routes)
	}

	if _, err := Routes([]config.Rule{{ID: "r", Actions: []string{"unknown"}}}, actions); err == nil {
		t.Error("expected an error for an unknown action")
	}
}

type recorder struct {
	mu  sync.Mutex
	got []string
}

func (r *recorder) Name() string { return "rec" }
func (r *recorder) Execute(_ context.Context, a *event.Alert) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.got = append(r.got, a.ID)
	return nil
}

func TestDispatcher(t *testing.T) {
	rec := &recorder{}
	d := NewDispatcher(context.Background(), map[string][]Action{"r1": {rec}}, 10, nil, nil)
	d.Dispatch(&event.Alert{ID: "a1", RuleID: "r1"})
	d.Dispatch(&event.Alert{ID: "a2", RuleID: "other"})
	d.Dispatch(&event.Alert{ID: "a3", RuleID: "r1"})
	d.Close()
	if strings.Join(rec.got, ",") != "a1,a3" {
		t.Errorf("got %v, want [a1 a3]", rec.got)
	}
}

func TestBuildWAFIPSet(t *testing.T) {
	t.Setenv("WAF_KEY", "AKIAEXAMPLE")
	t.Setenv("WAF_SECRET", "secret")
	t.Setenv("AWS_REGION", "")
	t.Setenv("AWS_CONFIG_FILE", "/nonexistent")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "/nonexistent")
	cfg := func(mod func(*config.Action)) config.Action {
		c := config.Action{ID: "waf", Type: "aws-waf-ipset",
			IPSet: config.WAFIPSet{Name: "blocklist"},
			AWS:   config.AWS{Region: "eu-west-3", AccessKeyIDEnv: "WAF_KEY", SecretAccessKeyEnv: "WAF_SECRET"},
		}
		if mod != nil {
			mod(&c)
		}
		return c
	}
	a, err := build(cfg(nil))
	if err != nil {
		t.Fatal(err)
	}
	if w := a.(*awswaf.IPSet); w.Name() != "waf" || w.SetName != "blocklist" || w.Scope != "REGIONAL" || w.Field != "SourceIP" || w.Remove {
		t.Errorf("default: %+v", w)
	}
	// CloudFront IP sets are in us-east-1.
	a, err = build(cfg(func(c *config.Action) {
		c.IPSet.Scope, c.IPSet.Operation, c.IPSet.Field = "CLOUDFRONT", "remove", "client_ip"
		c.AWS.Region = ""
	}))
	if err != nil {
		t.Fatal(err)
	}
	if w := a.(*awswaf.IPSet); w.Scope != "CLOUDFRONT" || !w.Remove || w.Field != "client_ip" {
		t.Errorf("cloudfront: %+v", w)
	}
	// An IP set for the IPv6 addresses.
	a, err = build(cfg(func(c *config.Action) { c.IPSet.IPv6Name, c.IPSet.IPv6ID = "blocklist6", "id6" }))
	if err != nil {
		t.Fatal(err)
	}
	if w := a.(*awswaf.IPSet); w.SetName != "blocklist" || w.IPv6SetName != "blocklist6" {
		t.Errorf("ipv6_name: %+v", w)
	}

	for _, tt := range []struct {
		mod  func(*config.Action)
		want string
	}{
		{func(c *config.Action) { c.IPSet.Name = "" }, "ipset.name is required"},
		{func(c *config.Action) { c.IPSet.Operation = "delete" }, `ipset.operation "delete": add or remove`},
		{func(c *config.Action) { c.IPSet.Scope = "GLOBAL" }, `ipset.scope "GLOBAL"`},
		{func(c *config.Action) { c.IPSet.IPv6ID = "id6" }, "ipset.ipv6_id requires ipset.ipv6_name"},
		{func(c *config.Action) { c.IPSet.IPv6Name = "blocklist" }, "must be another IP set than ipset.name"},
		{func(c *config.Action) { c.IPSet.Scope = "CLOUDFRONT" }, "the region must be us-east-1, not eu-west-3"},
		{func(c *config.Action) { c.IPSet.Field = " SourceIP" }, "unexpected spaces"},
		{func(c *config.Action) { c.AWS.Region = "" }, "aws: no region: set aws.region"},
		{func(c *config.Action) { c.AWS.SecretAccessKeyEnv = "" }, "aws: access_key_id_env and secret_access_key_env go together"},
		{func(c *config.Action) { c.AWS.AccessKeyIDEnv = "UNSET_WAF_KEY" }, "UNSET_WAF_KEY is not set"},
		{func(c *config.Action) { c.AWS.Profile = "p" }, "aws: set either keys"},
		{func(c *config.Action) { c.AWS = config.AWS{CredentialsFile: "/nonexistent/credentials"} }, "aws: credentials_file"},
		{func(c *config.Action) { c.AWS = config.AWS{Profile: "missing", Region: "eu-west-3"} }, "missing"},
	} {
		if _, err := build(cfg(tt.mod)); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("got %v, want %q", err, tt.want)
		}
	}
}

// The credentials of an aws-waf-ipset action come from the same settings as
// those of an aws-s3 source: here a profile of given files.
func TestBuildWAFIPSetProfile(t *testing.T) {
	dir := t.TempDir()
	creds := filepath.Join(dir, "credentials")
	conf := filepath.Join(dir, "config")
	os.WriteFile(creds, []byte("[wolverine]\naws_access_key_id = AKIAPROFILE\naws_secret_access_key = s\n"), 0o600)
	os.WriteFile(conf, []byte("[profile wolverine]\nregion = eu-central-1\n"), 0o600)
	t.Setenv("AWS_REGION", "")
	t.Setenv("AWS_PROFILE", "")
	a, err := build(config.Action{ID: "waf", Type: "aws-waf-ipset",
		IPSet: config.WAFIPSet{Name: "blocklist"},
		AWS:   config.AWS{Profile: "wolverine", CredentialsFile: creds, ConfigFile: conf},
	})
	if err != nil {
		t.Fatal(err)
	}
	if w := a.(*awswaf.IPSet); w.Client == nil {
		t.Fatal("no client")
	}
}

func TestBuildFile(t *testing.T) {
	dir := t.TempDir()
	ok := config.Action{ID: "f", Type: "file", File: config.FileAction{Path: filepath.Join(dir, "alerts.log")}}
	acts, err := Build([]config.Action{ok})
	if err != nil {
		t.Fatal(err)
	}
	if f, isFile := acts["f"].(*file.File); !isFile || f.Format != file.JSON {
		t.Errorf("action: %+v", acts["f"])
	}
	if _, err := os.Stat(ok.File.Path); err != nil {
		t.Errorf("the file is created at startup: %v", err)
	}
	for want, mod := range map[string]func(*config.Action){
		"file.path is required":           func(a *config.Action) { a.File.Path = "" },
		`file.format "xml": json or text`: func(a *config.Action) { a.File.Format = "xml" },
		"max_events must not be negative": func(a *config.Action) { a.MaxEvents = -1 },
		"file.path: open":                 func(a *config.Action) { a.File.Path = filepath.Join(dir, "nope", "alerts.log") },
	} {
		a := ok
		mod(&a)
		if _, err := Build([]config.Action{a}); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v", want, err)
		}
	}
}
