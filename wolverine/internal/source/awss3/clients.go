package awss3

import (
	"context"
	"errors"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sqs"

	"wolverine/internal/awsconf"
	"wolverine/internal/config"
)

// Clients holds the SQS and S3 clients of a source.
type Clients struct {
	SQS    *sqs.Client
	S3     *s3.Client
	Region string
	// Credentials tells where the credentials come from, for information.
	Credentials string
}

// NewClients creates the clients of a source from its aws settings (see
// awsconf.Load). The region is aws.region, else the one of the profile or AWS_REGION, else
// the one of the queue URL.
func NewClients(ctx context.Context, c config.AWS, queueURL string) (*Clients, error) {
	cfg, how, err := awsconf.Load(ctx, c)
	if err != nil {
		return nil, err
	}
	if cfg.Region == "" {
		cfg.Region = regionFromQueueURL(queueURL)
	}
	if cfg.Region == "" {
		return nil, errors.New("aws: no region: set aws.region")
	}

	sqsClient := sqs.NewFromConfig(cfg, func(o *sqs.Options) {
		if c.EndpointURL != "" {
			o.BaseEndpoint = aws.String(c.EndpointURL)
		}
	})
	s3Client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		// Log files delivered to S3 often have no checksum: do not log it
		// for each object.
		o.DisableLogOutputChecksumValidationSkipped = true
		if c.EndpointURL != "" {
			o.BaseEndpoint = aws.String(c.EndpointURL)
			// S3-compatible services rarely support bucket.host names.
			o.UsePathStyle = true
		}
	})
	return &Clients{SQS: sqsClient, S3: s3Client, Region: cfg.Region, Credentials: how}, nil
}

// regionFromQueueURL returns the region of a queue URL:
// https://sqs.eu-west-3.amazonaws.com/... or the older
// https://eu-west-3.queue.amazonaws.com/...
func regionFromQueueURL(queueURL string) string {
	u, err := url.Parse(queueURL)
	if err != nil {
		return ""
	}
	parts := strings.Split(u.Hostname(), ".")
	switch {
	case len(parts) >= 4 && parts[0] == "sqs":
		return parts[1]
	case len(parts) >= 4 && parts[1] == "queue":
		return parts[0]
	}
	return ""
}
