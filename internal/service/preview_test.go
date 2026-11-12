package service

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blagodaren/mirulesets/internal/config"
	"github.com/blagodaren/mirulesets/internal/model"
	"github.com/blagodaren/mirulesets/internal/rules"
	"github.com/blagodaren/mirulesets/internal/storage"
)

func TestPreviewAutoMatchesSourceParsing(t *testing.T) {
	fixtures := []struct {
		name, content, format string
	}{
		{name: "comments", content: "# comment\nexample.org\n", format: "text"},
		{name: "BOM YAML", content: "\xef\xbb\xbf# comment\n---\npayload:\n - example.org\n", format: "yaml"},
		{name: "flow YAML", content: `{"payload":["version"]}`, format: "yaml"},
		{name: "sing-box", content: `{"version":2,"rules":[{"domain_suffix":["example.org"]}]}`, format: "singbox"},
		{name: "hosts", content: "0.0.0.0 example.org\n", format: "hosts"},
		{name: "adblock", content: "[Adblock Plus 2.0]\n||example.org^\n", format: "adblock"},
	}
	mrs, err := rules.Encode([]string{"example.org", "+.example.com"}, "mrs", "domain")
	if err != nil {
		t.Fatal(err)
	}
	fixtures = append(fixtures, struct{ name, content, format string }{name: "MRS", content: string(mrs), format: "mrs"})
	for _, tc := range fixtures {
		t.Run(tc.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(tc.content))
			}))
			defer upstream.Close()
			s, err := New(config.Config{DataDir: t.TempDir(), AllowPrivateSources: true})
			if err != nil {
				t.Fatal(err)
			}
			preview, err := s.PreviewSource(context.Background(), upstream.URL, "auto", "domain")
			if err != nil {
				t.Fatal(err)
			}
			expected, err := rules.Parse([]byte(tc.content), "auto", "domain")
			if err != nil {
				t.Fatal(err)
			}
			built, err := s.source(context.Background(), model.Source{URL: upstream.URL, Format: "auto", Behavior: "domain"})
			if err != nil || !slices.Equal(built, expected) || !slices.Equal(preview.Lines, expected) || preview.Format != tc.format || preview.SizeBytes != len(tc.content) {
				t.Fatalf("preview=%+v build=%v expected=%v error=%v", preview, built, expected, err)
			}
		})
	}
}

func TestPreviewSharesSourceErrorsAndCache(t *testing.T) {
	var cached atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/missing":
			w.WriteHeader(http.StatusNotFound)
		case "/invalid":
			_, _ = w.Write([]byte("not/a/domain\n"))
		default:
			if r.Header.Get("If-None-Match") == `"rules"` {
				cached.Add(1)
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", `"rules"`)
			_, _ = w.Write([]byte("example.org\n"))
		}
	}))
	defer upstream.Close()
	s, err := New(config.Config{DataDir: t.TempDir(), AllowPrivateSources: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/missing", "/invalid"} {
		src := model.Source{URL: upstream.URL + path, Format: "auto", Behavior: "domain"}
		_, previewErr := s.PreviewSource(context.Background(), src.URL, src.Format, src.Behavior)
		_, sourceErr := s.source(context.Background(), src)
		if previewErr == nil || sourceErr == nil || previewErr.Error() != sourceErr.Error() {
			t.Fatalf("different errors: preview=%v source=%v", previewErr, sourceErr)
		}
	}
	for i := 0; i < 2; i++ {
		preview, err := s.PreviewSource(context.Background(), upstream.URL, "auto", "domain")
		if err != nil || preview.RuleCount != 1 || preview.SizeBytes != len("example.org\n") || preview.Format != "text" {
			t.Fatalf("cached preview: %+v %v", preview, err)
		}
	}
	if cached.Load() != 1 || len(s.Events()) != 0 || len(s.metrics) != 0 || len(s.Store.List()) != 0 {
		t.Fatal("preview did not reuse cache or changed persistent state")
	}
}

func TestPreviewConfiguredS3BucketOnly(t *testing.T) {
	var requests atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodGet || r.URL.Path != "/rulesets/import/rules.txt" {
			t.Errorf("unexpected S3 request: %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
		w.Header().Set("ETag", `"rules"`)
		w.Header().Set("Content-Length", fmt.Sprint(len("example.org\n")))
		_, _ = w.Write([]byte("example.org\n"))
	}))
	defer upstream.Close()
	s, err := New(config.Config{DataDir: t.TempDir(), S3: storage.Config{Endpoint: upstream.URL, Region: "us-east-1", Bucket: "rulesets", AccessKey: "test", SecretKey: "test", PathStyle: true, Prefix: "generated"}})
	if err != nil {
		t.Fatal(err)
	}
	preview, err := s.PreviewSource(context.Background(), "s3://rulesets/import/rules.txt", "auto", "domain")
	if err != nil || preview.Format != "text" || preview.SizeBytes != len("example.org\n") || !slices.Equal(preview.Lines, []string{"example.org"}) {
		t.Fatalf("S3 preview: %+v %v", preview, err)
	}
	_, err = s.PreviewSource(context.Background(), "s3://another-bucket/import/rules.txt", "auto", "domain")
	if err == nil || !strings.Contains(err.Error(), "настроенный bucket") || requests.Load() != 1 {
		t.Fatalf("unexpected bucket accepted: %v requests=%d", err, requests.Load())
	}
}
