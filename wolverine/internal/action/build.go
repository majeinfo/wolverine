package action

import (
	"context"
	"fmt"
	"net/mail"
	"net/url"
	"os"
	"os/exec"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	"github.com/aws/aws-sdk-go-v2/service/wafv2/types"

	"wolverine/internal/action/awswaf"
	"wolverine/internal/action/email"
	"wolverine/internal/action/ssh"
	"wolverine/internal/action/webhook"
	"wolverine/internal/awsconf"
	"wolverine/internal/config"
)

// Build creates the actions described in the configuration. Disabled actions
// are present in the map with a nil value, so that rules may still refer to
// them.
func Build(cfgs []config.Action) (map[string]Action, error) {
	actions := map[string]Action{}
	for i, c := range cfgs {
		if c.ID == "" {
			return nil, fmt.Errorf("action #%d: missing id", i+1)
		}
		if _, dup := actions[c.ID]; dup {
			return nil, fmt.Errorf("action %q: duplicate id", c.ID)
		}
		if c.Disabled {
			actions[c.ID] = nil
			continue
		}
		a, err := build(c)
		if err != nil {
			return nil, fmt.Errorf("action %q: %w", c.ID, err)
		}
		actions[c.ID] = a
	}
	return actions, nil
}

func build(c config.Action) (Action, error) {
	switch c.Type {
	case "email":
		return buildEmail(c)
	case "ssh":
		return buildSSH(c)
	case "webhook":
		return buildWebhook(c)
	case "aws-waf-ipset":
		return buildWAFIPSet(c)
	case "":
		return nil, fmt.Errorf("missing type")
	default:
		return nil, fmt.Errorf("unknown type %q", c.Type)
	}
}

func buildEmail(c config.Action) (Action, error) {
	if c.SMTP.Host == "" {
		return nil, fmt.Errorf("smtp.host is required")
	}
	port := c.SMTP.Port
	if port == 0 {
		port = 25
	}
	if _, err := mail.ParseAddress(c.From); err != nil {
		return nil, fmt.Errorf("from %q: %w", c.From, err)
	}
	if len(c.To) == 0 {
		return nil, fmt.Errorf("to: at least one recipient is required")
	}
	for _, to := range c.To {
		if _, err := mail.ParseAddress(to); err != nil {
			return nil, fmt.Errorf("to %q: %w", to, err)
		}
	}

	var password string
	if c.SMTP.PasswordEnv != "" {
		var ok bool
		if password, ok = os.LookupEnv(c.SMTP.PasswordEnv); !ok {
			return nil, fmt.Errorf("environment variable %s (smtp.password_env) is not set", c.SMTP.PasswordEnv)
		}
	}

	return &email.Email{
		ID:        c.ID,
		Host:      c.SMTP.Host,
		Port:      port,
		Username:  c.SMTP.Username,
		Password:  password,
		From:      c.From,
		To:        c.To,
		Timeout:   c.SMTP.Timeout,
		MaxEvents: c.MaxEvents,
	}, nil
}

func buildSSH(c config.Action) (Action, error) {
	if c.SSH.Host == "" {
		return nil, fmt.Errorf("ssh.host is required")
	}
	if strings.HasPrefix(c.SSH.Host, "-") {
		return nil, fmt.Errorf("ssh.host %q: invalid host", c.SSH.Host)
	}
	if c.Command == "" {
		return nil, fmt.Errorf("command is required")
	}
	tmpl, err := ssh.ParseCommand(c.Command)
	if err != nil {
		return nil, fmt.Errorf("command: %w", err)
	}
	if c.SSH.IdentityFile != "" {
		if _, err := os.Stat(c.SSH.IdentityFile); err != nil {
			return nil, fmt.Errorf("ssh.identity_file: %w", err)
		}
	}
	if _, err := exec.LookPath("ssh"); err != nil {
		return nil, fmt.Errorf("ssh client not found: %w", err)
	}

	return &ssh.SSH{
		ID:           c.ID,
		Host:         c.SSH.Host,
		Port:         c.SSH.Port,
		User:         c.SSH.User,
		IdentityFile: c.SSH.IdentityFile,
		Command:      tmpl,
		Timeout:      c.SSH.Timeout,
	}, nil
}

func buildWebhook(c config.Action) (Action, error) {
	rawURL := c.Webhook.URL
	switch {
	case rawURL != "" && c.Webhook.URLEnv != "":
		return nil, fmt.Errorf("webhook: set url or url_env, not both")
	case c.Webhook.URLEnv != "":
		var ok bool
		if rawURL, ok = os.LookupEnv(c.Webhook.URLEnv); !ok {
			return nil, fmt.Errorf("environment variable %s (webhook.url_env) is not set", c.Webhook.URLEnv)
		}
	}
	// The URL may be a secret: do not print it.
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("webhook: an http:// or https:// URL is required (url or url_env)")
	}
	if c.Webhook.Retries < 0 {
		return nil, fmt.Errorf("webhook.retries must not be negative")
	}

	headers := map[string]string{}
	for k, v := range c.Webhook.Headers {
		headers[k] = v
	}
	for k, env := range c.Webhook.HeadersEnv {
		v, ok := os.LookupEnv(env)
		if !ok {
			return nil, fmt.Errorf("environment variable %s (webhook.headers_env.%s) is not set", env, k)
		}
		headers[k] = v
	}
	for k, v := range headers {
		if k == "" || strings.ContainsAny(k, " :\r\n") || strings.ContainsAny(v, "\r\n") {
			return nil, fmt.Errorf("webhook: invalid header %q", k)
		}
	}

	var body *webhook.Body
	if c.Webhook.Body != "" {
		if body, err = webhook.ParseBody(c.Webhook.Body, c.Webhook.Escape); err != nil {
			return nil, fmt.Errorf("webhook.body: %w", err)
		}
	} else if c.Webhook.Escape != "" {
		return nil, fmt.Errorf("webhook.escape is only used with webhook.body")
	}

	return &webhook.Webhook{
		ID:        c.ID,
		URL:       rawURL,
		Body:      body,
		Headers:   headers,
		Timeout:   c.Webhook.Timeout,
		Retries:   c.Webhook.Retries,
		MaxEvents: c.MaxEvents,
	}, nil
}

func buildWAFIPSet(c config.Action) (Action, error) {
	s := c.IPSet
	if s.Name == "" {
		return nil, fmt.Errorf("ipset.name is required")
	}
	var remove bool
	switch s.Operation {
	case "", "add":
	case "remove":
		remove = true
	default:
		return nil, fmt.Errorf("ipset.operation %q: add or remove", s.Operation)
	}
	field := s.Field
	if field == "" {
		field = "SourceIP"
	}
	if strings.TrimSpace(field) != field {
		return nil, fmt.Errorf("ipset.field %q: unexpected spaces", field)
	}
	awsCfg := c.AWS
	var scope types.Scope
	switch s.Scope {
	case "", "REGIONAL":
		scope = types.ScopeRegional
	case "CLOUDFRONT":
		// The IP sets of CloudFront are in us-east-1.
		if awsCfg.Region != "" && awsCfg.Region != "us-east-1" {
			return nil, fmt.Errorf("ipset.scope CLOUDFRONT: the region must be us-east-1, not %s (aws.region)", awsCfg.Region)
		}
		awsCfg.Region = "us-east-1"
		scope = types.ScopeCloudfront
	default:
		return nil, fmt.Errorf("ipset.scope %q: REGIONAL or CLOUDFRONT", s.Scope)
	}
	if s.Timeout < 0 {
		return nil, fmt.Errorf("ipset.timeout must not be negative")
	}
	cfg, _, err := awsconf.Load(context.Background(), awsCfg)
	if err != nil {
		return nil, err
	}
	if cfg.Region == "" {
		return nil, fmt.Errorf("aws: no region: set aws.region")
	}
	client := wafv2.NewFromConfig(cfg, func(o *wafv2.Options) {
		if awsCfg.EndpointURL != "" {
			o.BaseEndpoint = aws.String(awsCfg.EndpointURL)
		}
	})
	return awswaf.New(c.ID, client, s.Name, s.ID, scope, field, remove, s.Timeout), nil
}

// Routes maps each enabled rule id to the actions it triggers.
func Routes(rules []config.Rule, actions map[string]Action) (map[string][]Action, error) {
	routes := map[string][]Action{}
	for _, r := range rules {
		if r.Disabled {
			continue
		}
		for _, id := range r.Actions {
			a, ok := actions[id]
			if !ok {
				return nil, fmt.Errorf("rule %q: unknown action %q", r.ID, id)
			}
			if a != nil {
				routes[r.ID] = append(routes[r.ID], a)
			}
		}
	}
	return routes, nil
}
