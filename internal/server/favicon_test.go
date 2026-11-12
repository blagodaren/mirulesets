package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/blagodaren/mirulesets/internal/config"
	"github.com/blagodaren/mirulesets/internal/service"
	"github.com/blagodaren/mirulesets/web"
)

func TestFavicon(t *testing.T) {
	svc, err := service.New(config.Config{DataDir: t.TempDir(), Password: "test-password-12345"})
	if err != nil {
		t.Fatal(err)
	}
	h, err := New(svc)
	if err != nil {
		t.Fatal(err)
	}
	want, err := web.Files.ReadFile("favicon.svg")
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		t.Run(method, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(method, "/favicon.svg", nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rec.Code)
			}
			if got := rec.Header().Get("Content-Type"); got != "image/svg+xml" {
				t.Fatalf("Content-Type = %q", got)
			}
			if got := rec.Header().Get("Cache-Control"); got != "no-cache" {
				t.Fatalf("Cache-Control = %q", got)
			}
			if method == http.MethodGet && !bytes.Equal(rec.Body.Bytes(), want) {
				t.Fatal("response differs from embedded favicon")
			}
			if method == http.MethodHead && rec.Body.Len() != 0 {
				t.Fatal("HEAD response has a body")
			}
		})
	}
}
