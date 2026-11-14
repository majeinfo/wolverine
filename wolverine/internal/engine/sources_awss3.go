package engine

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"time"

	"wolverine/internal/config"
	"wolverine/internal/source/awss3"
	"wolverine/internal/verbose"
)

// maxVisibility is the longest visibility timeout SQS accepts.
const maxVisibility = 12 * time.Hour

func buildAWSS3(c config.Source) (*input, error) {
	if c.QueueURL == "" {
		return nil, errors.New("queue_url is required")
	}
	if u, err := url.Parse(c.QueueURL); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, fmt.Errorf("queue_url %q: an https:// URL is required", c.QueueURL)
	}
	if c.VisibilityTimeout < 0 || c.VisibilityTimeout > maxVisibility || c.VisibilityTimeout%time.Second != 0 {
		return nil, fmt.Errorf("visibility_timeout: whole seconds, at most %s", maxVisibility)
	}
	if c.VisibilityTimeout > 0 && c.VisibilityTimeout < 10*time.Second {
		return nil, errors.New("visibility_timeout: at least 10s")
	}
	var keyRe *regexp.Regexp
	if c.KeyRegexp != "" {
		var err error
		if keyRe, err = regexp.Compile(c.KeyRegexp); err != nil {
			return nil, fmt.Errorf("key_regexp: %w", err)
		}
	}
	p, err := lineParser(c)
	if err != nil {
		return nil, err
	}

	clients, err := awss3.NewClients(context.Background(), c.AWS, c.QueueURL)
	if err != nil {
		return nil, err
	}
	verbose.Infof("source %s: region %s, credentials from %s", c.ID, clients.Region, clients.Credentials)

	return &input{
		source: &awss3.Source{
			ID:                c.ID,
			QueueURL:          c.QueueURL,
			KeyRegexp:         keyRe,
			Follow:            c.Follow,
			VisibilityTimeout: c.VisibilityTimeout,
			SkipLines:         c.SkipLines,
			SQS:               clients.SQS,
			S3:                clients.S3,
		},
		parser: p,
	}, nil
}
