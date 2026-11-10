package awss3

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sqs"

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

// NewClients creates the clients of a source from its aws settings:
//   - access_key_id_env and secret_access_key_env (and session_token_env):
//     keys read from these environment variables;
//   - otherwise profile, credentials_file and config_file select the shared
//     files and the profile to use;
//   - otherwise the AWS SDK's defaults: AWS_* environment variables, the
//     default profile of ~/.aws, the EC2 instance or ECS task role.
//
// The region is aws.region, else the one of the profile or AWS_REGION, else
// the one of the queue URL.
func NewClients(ctx context.Context, c config.AWS, queueURL string) (*Clients, error) {
	var opts []func(*awsconfig.LoadOptions) error
	how := "the AWS SDK's defaults"

	if c.AccessKeyIDEnv != "" || c.SecretAccessKeyEnv != "" || c.SessionTokenEnv != "" {
		if c.AccessKeyIDEnv == "" || c.SecretAccessKeyEnv == "" {
			return nil, errors.New("aws: access_key_id_env and secret_access_key_env go together")
		}
		if c.Profile != "" || c.CredentialsFile != "" {
			return nil, errors.New("aws: set either keys (access_key_id_env...), or profile and credentials_file")
		}
		var keys [3]string
		for i, name := range []string{c.AccessKeyIDEnv, c.SecretAccessKeyEnv, c.SessionTokenEnv} {
			if name == "" {
				continue
			}
			if keys[i] = os.Getenv(name); keys[i] == "" {
				return nil, fmt.Errorf("aws: environment variable %s is not set", name)
			}
		}
		opts = append(opts, awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(keys[0], keys[1], keys[2])))
		how = "$" + c.AccessKeyIDEnv
	}
	if c.CredentialsFile != "" {
		if _, err := os.Stat(c.CredentialsFile); err != nil {
			return nil, fmt.Errorf("aws: credentials_file: %w", err)
		}
		opts = append(opts, awsconfig.WithSharedCredentialsFiles([]string{c.CredentialsFile}))
		how = c.CredentialsFile
	}
	if c.ConfigFile != "" {
		if _, err := os.Stat(c.ConfigFile); err != nil {
			return nil, fmt.Errorf("aws: config_file: %w", err)
		}
		opts = append(opts, awsconfig.WithSharedConfigFiles([]string{c.ConfigFile}))
	}
	if c.Profile != "" {
		opts = append(opts, awsconfig.WithSharedConfigProfile(c.Profile))
		how = "profile " + c.Profile
		if c.CredentialsFile != "" {
			how += " of " + c.CredentialsFile
		}
	}
	if c.Region != "" {
		opts = append(opts, awsconfig.WithRegion(c.Region))
	}

	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("aws: %w", err)
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
