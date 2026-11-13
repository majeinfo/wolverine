// Package awsconf loads the AWS configuration (credentials, region) of a
// source or an action from its aws settings.
package awsconf

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"

	"wolverine/internal/config"
)

// Load returns the AWS configuration of the aws settings, and tells where
// the credentials come from, for information:
//   - access_key_id_env and secret_access_key_env (and session_token_env):
//     keys read from these environment variables;
//   - otherwise profile, credentials_file and config_file select the shared
//     files and the profile to use;
//   - otherwise the AWS SDK's defaults: AWS_* environment variables, the
//     default profile of ~/.aws, the EC2 instance or ECS task role.
//
// The region is aws.region, else the one of the profile or AWS_REGION; it
// may be empty.
func Load(ctx context.Context, c config.AWS) (aws.Config, string, error) {
	var opts []func(*awsconfig.LoadOptions) error
	how := "the AWS SDK's defaults"

	if c.AccessKeyIDEnv != "" || c.SecretAccessKeyEnv != "" || c.SessionTokenEnv != "" {
		if c.AccessKeyIDEnv == "" || c.SecretAccessKeyEnv == "" {
			return aws.Config{}, "", errors.New("aws: access_key_id_env and secret_access_key_env go together")
		}
		if c.Profile != "" || c.CredentialsFile != "" {
			return aws.Config{}, "", errors.New("aws: set either keys (access_key_id_env...), or profile and credentials_file")
		}
		var keys [3]string
		for i, name := range []string{c.AccessKeyIDEnv, c.SecretAccessKeyEnv, c.SessionTokenEnv} {
			if name == "" {
				continue
			}
			if keys[i] = os.Getenv(name); keys[i] == "" {
				return aws.Config{}, "", fmt.Errorf("aws: environment variable %s is not set", name)
			}
		}
		opts = append(opts, awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(keys[0], keys[1], keys[2])))
		how = "$" + c.AccessKeyIDEnv
	}
	if c.CredentialsFile != "" {
		if _, err := os.Stat(c.CredentialsFile); err != nil {
			return aws.Config{}, "", fmt.Errorf("aws: credentials_file: %w", err)
		}
		opts = append(opts, awsconfig.WithSharedCredentialsFiles([]string{c.CredentialsFile}))
		how = c.CredentialsFile
	}
	if c.ConfigFile != "" {
		if _, err := os.Stat(c.ConfigFile); err != nil {
			return aws.Config{}, "", fmt.Errorf("aws: config_file: %w", err)
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
		return aws.Config{}, "", fmt.Errorf("aws: %w", err)
	}
	return cfg, how, nil
}
