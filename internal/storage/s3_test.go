package storage

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func testConfig(endpoint string) Config {
	return Config{Endpoint: endpoint, Region: "us-east-1", Bucket: "rulesets", AccessKey: "test-access", SecretKey: "test-secret", PathStyle: true}
}

func TestS3PublishMetadataAndPublicURL(t *testing.T) {
	data := []byte("+.example.com\n")
	hash := sha256.Sum256(data)
	md5sum := md5.Sum(data)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/rulesets/generated/domain list.txt" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		for header, want := range map[string]string{
			"Content-Type":      "text/plain; charset=utf-8",
			"Cache-Control":     "max-age=300, must-revalidate",
			"X-Amz-Meta-Sha256": hex.EncodeToString(hash[:]),
			"Content-Md5":       base64.StdEncoding.EncodeToString(md5sum[:]),
		} {
			if got := r.Header.Get(header); got != want {
				t.Errorf("%s: got %q, want %q", header, got, want)
			}
		}
		if r.Header.Get("X-Amz-Acl") != "" {
			t.Error("upload must not change object ACL")
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
			t.Error("missing SigV4 authorization")
		}
		body, _ := io.ReadAll(r.Body)
		if !bytes.Contains(body, data) {
			t.Errorf("payload missing from upload body")
		}
		w.Header().Set("ETag", `"test-etag"`)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	cfg := testConfig(server.URL)
	cfg.Prefix = "generated"
	cfg.PublicURL = "https://cdn.example.com/objects"
	store, err := NewS3(cfg)
	if err != nil {
		t.Fatal(err)
	}
	got, err := store.Put(context.Background(), "domain list.txt", "text/plain; charset=utf-8", data)
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://cdn.example.com/objects/generated/domain%20list.txt" {
		t.Fatalf("public URL %q", got)
	}
}

func TestS3GetExactKeyAndPrivatePublication(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			if r.URL.Path != "/rulesets/import/source.txt" {
				t.Errorf("Get added prefix: %s", r.URL.Path)
			}
			w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
			w.Header().Set("ETag", `"test-etag"`)
			w.Header().Set("Content-Length", "12")
			io.WriteString(w, "example.com\n")
		case http.MethodPut:
			io.Copy(io.Discard, r.Body)
			w.Header().Set("ETag", `"test-etag"`)
		case http.MethodHead:
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL)
		}
	}))
	defer server.Close()
	cfg := testConfig(server.URL)
	cfg.Prefix = "generated"
	store, err := NewS3(cfg)
	if err != nil {
		t.Fatal(err)
	}
	got, err := store.Get(context.Background(), "import/source.txt")
	if err != nil || string(got) != "example.com\n" {
		t.Fatalf("Get: %q, %v", got, err)
	}
	link, err := store.Put(context.Background(), "private.txt", "text/plain", got)
	if err != nil || link != "" {
		t.Fatalf("private Put: link=%q, error=%v", link, err)
	}
	if err := store.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestS3GetLimitAndErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/missing.txt") {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, "<Error><Code>NoSuchKey</Code><Message>missing</Message></Error>")
			return
		}
		w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
		w.Header().Set("ETag", `"large"`)
		w.Header().Set("Content-Length", strconv.Itoa(MaxObjectBytes+1))
		chunk := make([]byte, 32*1024)
		for written := 0; written < MaxObjectBytes; written += len(chunk) {
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
		w.Write([]byte{0})
	}))
	defer server.Close()
	store, err := NewS3(testConfig(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(context.Background(), "missing.txt"); err == nil {
		t.Fatal("missing object accepted")
	}
	if _, err := store.Get(context.Background(), "large.txt"); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected size limit error, got %v", err)
	}
}

func TestS3Validation(t *testing.T) {
	for _, key := range []string{"", "../escape", "/absolute", "a/../b", "a//b", "a\\b", "a\nB"} {
		if err := validateKey(key); err == nil {
			t.Errorf("accepted key %q", key)
		}
	}
	for _, endpoint := range []string{"https://user:secret@example.com", "https://example.com/path", "ftp://example.com", "https://example.com?secret=x"} {
		if _, err := NewS3(testConfig(endpoint)); err == nil {
			t.Errorf("accepted endpoint %q", endpoint)
		}
	}
	cfg := testConfig("https://s3.example.com")
	cfg.PublicURL = "https://user:secret@cdn.example.com"
	if _, err := NewS3(cfg); err == nil {
		t.Fatal("accepted credentials in public URL")
	}
}

func TestS3CheckMissingBucket(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNotFound) }))
	defer server.Close()
	store, err := NewS3(testConfig(server.URL))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Check(context.Background()); err == nil {
		t.Fatal("missing bucket accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.Put(ctx, "cancelled.txt", "text/plain", []byte("data")); err == nil {
		t.Fatal("cancelled upload succeeded")
	}
}
