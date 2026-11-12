// Package storage publishes generated rulesets to S3-compatible object stores.
package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/minio/minio-go/v7/pkg/s3utils"
)

const MaxObjectBytes = 32 << 20

// Config is populated from server-side environment variables, never from the API.
// PublicURL is the public/CDN URL of the bucket root; Prefix is added to uploads.
type Config struct {
	Endpoint, Region, Bucket           string
	AccessKey, SecretKey, SessionToken string
	Prefix, PublicURL                  string
	Secure, PathStyle                  bool
}

type S3 struct {
	client    *minio.Client
	bucket    string
	prefix    string
	publicURL *url.URL
}

func NewS3(cfg Config) (*S3, error) {
	if cfg.Endpoint == "" || cfg.Bucket == "" {
		return nil, errors.New("S3 endpoint and bucket are required")
	}
	if cfg.AccessKey == "" || cfg.SecretKey == "" {
		return nil, errors.New("S3 access key and secret key are required")
	}
	if err := s3utils.CheckValidBucketNameStrict(cfg.Bucket); err != nil {
		return nil, fmt.Errorf("invalid S3 bucket: %w", err)
	}
	endpoint := cfg.Endpoint
	secure := cfg.Secure
	if strings.Contains(endpoint, "://") {
		u, err := url.Parse(endpoint)
		if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
			return nil, errors.New("S3 endpoint must be an HTTP(S) host without credentials, path, or query")
		}
		endpoint, secure = u.Host, u.Scheme == "https"
	}
	prefix := strings.Trim(cfg.Prefix, "/")
	if prefix != "" {
		if err := validateKey(prefix); err != nil {
			return nil, fmt.Errorf("invalid S3 prefix: %w", err)
		}
	}
	var publicURL *url.URL
	if cfg.PublicURL != "" {
		u, err := url.Parse(cfg.PublicURL)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return nil, errors.New("S3 public URL must be an HTTP(S) URL without credentials, query, or fragment")
		}
		publicURL = u
	}
	lookup := minio.BucketLookupAuto
	if cfg.PathStyle {
		lookup = minio.BucketLookupPath
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ResponseHeaderTimeout = 30 * time.Second
	transport.MaxIdleConnsPerHost = 8
	client, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, cfg.SessionToken),
		Secure: secure, Region: cfg.Region, BucketLookup: lookup,
		Transport: transport, MaxRetries: 3,
	})
	if err != nil {
		return nil, fmt.Errorf("create S3 client: %w", err)
	}
	client.SetAppInfo("MIRulesets", "1")
	return &S3{client: client, bucket: cfg.Bucket, prefix: prefix, publicURL: publicURL}, nil
}

// Put uploads under Prefix and returns a public URL only when explicitly configured.
// Uploading never changes bucket policy or sets a public ACL.
func (s *S3) Put(ctx context.Context, key, contentType string, data []byte) (string, error) {
	if err := validateKey(key); err != nil {
		return "", err
	}
	if s.prefix != "" {
		key = s.prefix + "/" + key
	}
	hash := sha256.Sum256(data)
	_, err := s.client.PutObject(ctx, s.bucket, key, bytes.NewReader(data), int64(len(data)), minio.PutObjectOptions{
		ContentType: contentType, CacheControl: "max-age=300, must-revalidate",
		UserMetadata:   map[string]string{"sha256": hex.EncodeToString(hash[:])},
		SendContentMd5: true, DisableMultipart: true,
	})
	if err != nil {
		return "", fmt.Errorf("upload S3 object: %w", err)
	}
	if s.publicURL == nil {
		return "", nil
	}
	u := *s.publicURL
	u.Path = strings.TrimRight(u.Path, "/") + "/" + key
	u.RawPath = ""
	return u.String(), nil
}

// Get reads an exact bucket key (without adding Prefix), e.g. the path in s3://bucket/key.
func (s *S3) Get(ctx context.Context, key string) ([]byte, error) {
	if err := validateKey(key); err != nil {
		return nil, err
	}
	obj, err := s.client.GetObject(ctx, s.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("open S3 object: %w", err)
	}
	defer obj.Close()
	data, err := io.ReadAll(io.LimitReader(obj, MaxObjectBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read S3 object: %w", err)
	}
	if len(data) > MaxObjectBytes {
		return nil, fmt.Errorf("S3 object exceeds %d bytes", MaxObjectBytes)
	}
	return data, nil
}

// Delete removes only an exact service-owned key under the configured prefix.
func (s *S3) Delete(ctx context.Context, key string) error {
	if err := validateKey(key); err != nil {
		return err
	}
	if s.prefix != "" {
		key = s.prefix + "/" + key
	}
	if err := s.client.RemoveObject(ctx, s.bucket, key, minio.RemoveObjectOptions{}); err != nil {
		return fmt.Errorf("delete S3 object: %w", err)
	}
	return nil
}

// Check checks bucket reachability/existence. It does not create the bucket or
// probe write permission by uploading temporary data.
func (s *S3) Check(ctx context.Context) error {
	exists, err := s.client.BucketExists(ctx, s.bucket)
	if err != nil {
		return fmt.Errorf("check S3 bucket: %w", err)
	}
	if !exists {
		return errors.New("S3 bucket does not exist")
	}
	return nil
}

func validateKey(key string) error {
	if key == "" || len(key) > 1024 || strings.HasPrefix(key, "/") || strings.ContainsAny(key, "\\\x00\r\n") {
		return errors.New("invalid S3 object key")
	}
	for _, part := range strings.Split(key, "/") {
		if part == "" || part == "." || part == ".." {
			return errors.New("S3 object key must not contain empty or relative path segments")
		}
	}
	return nil
}
