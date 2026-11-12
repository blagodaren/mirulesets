package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/blagodaren/mirulesets/internal/config"
	"github.com/blagodaren/mirulesets/internal/fetcher"
	"github.com/blagodaren/mirulesets/internal/rules"
	"github.com/blagodaren/mirulesets/internal/service"
)

const previewTestToken = "preview-test-token-1234567890123456"

func previewTestHandler(t *testing.T, allowPrivate bool) (*service.Service, http.Handler) {
	t.Helper()
	svc, err := service.New(config.Config{DataDir: t.TempDir(), Password: "test-password-12345", APIToken: previewTestToken, AllowPrivateSources: allowPrivate})
	if err != nil {
		t.Fatal(err)
	}
	h, err := New(svc)
	if err != nil {
		t.Fatal(err)
	}
	return svc, h
}

func previewRequest(ctx context.Context, rawURL, format, behavior string) *http.Request {
	body, _ := json.Marshal(map[string]string{"url": rawURL, "format": format, "behavior": behavior})
	req := httptest.NewRequest(http.MethodPost, "http://localhost/api/preview", bytes.NewReader(body)).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+previewTestToken)
	return req
}

func TestPreviewAuthenticationAndRemovedRoute(t *testing.T) {
	_, h := previewTestHandler(t, false)
	req := previewRequest(context.Background(), "https://example.org/rules.mrs", "auto", "domain")
	req.Header.Del("Authorization")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated preview: %d %s", rec.Code, rec.Body.String())
	}
	req = httptest.NewRequest(http.MethodPost, "http://localhost/api/convert", nil)
	req.Header.Set("Authorization", "Bearer "+previewTestToken)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("removed route: %d %s", rec.Code, rec.Body.String())
	}
	login := httptest.NewRequest(http.MethodPost, "http://localhost/api/login", strings.NewReader(`{"password":"test-password-12345"}`))
	login.Header.Set("X-Requested-With", "MIRulesets")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, login)
	if rec.Code != http.StatusOK || len(rec.Result().Cookies()) == 0 {
		t.Fatalf("login: %d %s", rec.Code, rec.Body.String())
	}
	cookie := rec.Result().Cookies()[0]
	for _, tc := range []struct {
		name, origin string
		csrf         bool
		want         int
	}{
		{name: "missing CSRF header", want: http.StatusForbidden},
		{name: "cross origin", origin: "https://other.example", csrf: true, want: http.StatusForbidden},
		{name: "same origin", origin: "http://localhost", csrf: true, want: http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := previewRequest(context.Background(), "http://127.0.0.1/rules.txt", "auto", "domain")
			req.Header.Del("Authorization")
			req.AddCookie(cookie)
			if tc.csrf {
				req.Header.Set("X-Requested-With", "MIRulesets")
			}
			req.Header.Set("Origin", tc.origin)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status: %d %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestPreviewSources(t *testing.T) {
	lines := make([]string, 205)
	for i := range lines {
		lines[i] = fmt.Sprintf("domain-%03d.example", i)
	}
	fixtures := map[string][]byte{}
	for _, format := range []string{"mrs", "text", "yaml"} {
		data, err := rules.Encode(lines, format, "domain")
		if err != nil {
			t.Fatal(err)
		}
		fixtures["/large."+format] = data
	}
	fixtures["/small.text"] = []byte("# comment\nexample.org\n+.example.com\nexample.org\n")
	fixtures["/exact.text"] = []byte(strings.Join(lines[:200], "\n"))
	fixtures["/empty.text"] = []byte("# no rules\n")
	fixtures["/bom.yaml"] = []byte("\xef\xbb\xbf# comment\n---\npayload:\n  - example.org\n")
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(fixtures[r.URL.Path])
	}))
	defer upstream.Close()
	svc, h := previewTestHandler(t, true)
	beforeSets, _ := json.Marshal(svc.Store.List())
	beforeEvents, _ := json.Marshal(svc.Events())
	for _, tc := range []struct {
		path, input, format string
		count               int
		truncated           bool
	}{
		{path: "/large.mrs", input: "auto", format: "mrs", count: 205, truncated: true},
		{path: "/large.mrs", input: "mrs", format: "mrs", count: 205, truncated: true},
		{path: "/large.text", input: "auto", format: "text", count: 205, truncated: true},
		{path: "/large.yaml", input: "auto", format: "yaml", count: 205, truncated: true},
		{path: "/small.text", input: "text", format: "text", count: 2},
		{path: "/exact.text", input: "auto", format: "text", count: 200},
		{path: "/empty.text", input: "auto", format: "text", count: 0},
		{path: "/bom.yaml", input: "auto", format: "yaml", count: 1},
	} {
		t.Run(tc.path+"/"+tc.input, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, previewRequest(context.Background(), upstream.URL+tc.path, tc.input, "domain"))
			if rec.Code != http.StatusOK {
				t.Fatalf("preview: %d %s", rec.Code, rec.Body.String())
			}
			var result service.SourcePreview
			if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if result.RuleCount != tc.count || result.Format != tc.format || result.Behavior != "domain" || result.Truncated != tc.truncated || result.SizeBytes != len(fixtures[tc.path]) {
				t.Fatalf("unexpected metadata: %+v", result)
			}
			expected, err := rules.Parse(fixtures[tc.path], tc.input, "domain")
			if err != nil {
				t.Fatal(err)
			}
			if len(expected) > 200 {
				expected = expected[:200]
			}
			if !reflect.DeepEqual(result.Lines, expected) {
				t.Fatalf("preview lines differ from parsed rules: %v", result.Lines)
			}
		})
	}
	afterSets, _ := json.Marshal(svc.Store.List())
	afterEvents, _ := json.Marshal(svc.Events())
	if !bytes.Equal(beforeSets, afterSets) || !bytes.Equal(beforeEvents, afterEvents) {
		t.Fatal("preview changed stored rulesets or events")
	}
}

func TestPreviewRejectsInvalidSources(t *testing.T) {
	_, guarded := previewTestHandler(t, false)
	rec := httptest.NewRecorder()
	guarded.ServeHTTP(rec, previewRequest(context.Background(), "http://127.0.0.1/rules.txt", "auto", "domain"))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "приватный или служебный адрес") {
		t.Fatalf("private source: %d %s", rec.Code, rec.Body.String())
	}
	mrs, err := rules.Encode([]string{"example.org"}, "mrs", "domain")
	if err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/too-large":
			w.Header().Set("Content-Length", fmt.Sprint(fetcher.MaxBytes+1))
		case "/missing":
			w.WriteHeader(http.StatusNotFound)
		default:
			_, _ = w.Write(mrs)
		}
	}))
	defer upstream.Close()
	_, h := previewTestHandler(t, true)
	for _, tc := range []struct {
		url, format, behavior, errorText string
	}{
		{url: "file:///rules.txt", format: "auto", behavior: "domain", errorText: "источник должен использовать"},
		{url: "s3://other-bucket/rules.mrs", format: "auto", behavior: "domain", errorText: "настроенный bucket"},
		{url: upstream.URL, format: "unsupported", behavior: "domain", errorText: "неизвестный формат"},
		{url: upstream.URL, format: "auto", behavior: "unsupported", errorText: "неизвестный behavior"},
		{url: upstream.URL, format: "auto", behavior: "ipcidr", errorText: "MRS"},
		{url: upstream.URL + "/too-large", format: "auto", behavior: "domain", errorText: "32 MiB"},
		{url: upstream.URL + "/missing", format: "auto", behavior: "domain", errorText: "HTTP 404"},
	} {
		t.Run(tc.errorText, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, previewRequest(context.Background(), tc.url, tc.format, tc.behavior))
			if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), tc.errorText) {
				t.Fatalf("invalid source: %d %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestPreviewConcurrencyAndCancellation(t *testing.T) {
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/wait" {
			started <- struct{}{}
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}
		_, _ = w.Write([]byte("example.org\n"))
	}))
	defer upstream.Close()
	defer close(release)
	_, h := previewTestHandler(t, true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan *httptest.ResponseRecorder, 2)
	for i := 0; i < 2; i++ {
		go func() {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, previewRequest(ctx, upstream.URL+"/wait", "auto", "domain"))
			done <- rec
		}()
	}
	for i := 0; i < 2; i++ {
		select {
		case <-started:
		case <-time.After(3 * time.Second):
			t.Fatal("preview did not start")
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, previewRequest(context.Background(), upstream.URL, "auto", "domain"))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("third preview: %d %s", rec.Code, rec.Body.String())
	}
	cancel()
	for i := 0; i < 2; i++ {
		select {
		case rec := <-done:
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("canceled preview: %d %s", rec.Code, rec.Body.String())
			}
		case <-time.After(3 * time.Second):
			t.Fatal("preview ignored cancellation")
		}
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, previewRequest(context.Background(), upstream.URL, "auto", "domain"))
	if rec.Code != http.StatusOK {
		t.Fatalf("preview slots not released: %d %s", rec.Code, rec.Body.String())
	}
	deadline, stop := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer stop()
	start := time.Now()
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, previewRequest(deadline, upstream.URL+"/wait", "auto", "domain"))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "context deadline exceeded") || time.Since(start) > 3*time.Second {
		t.Fatalf("preview ignored request deadline: %d %s", rec.Code, rec.Body.String())
	}
}
