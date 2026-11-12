package server

import (
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blagodaren/mirulesets/internal/config"
	"github.com/blagodaren/mirulesets/internal/service"
)

func TestEmbeddedFonts(t *testing.T) {
	svc, err := service.New(config.Config{DataDir: t.TempDir(), Password: "test-password-12345"})
	if err != nil {
		t.Fatal(err)
	}
	h, err := New(svc)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"geist-cyrillic-wght-normal.woff2",
		"geist-latin-wght-normal.woff2",
		"geist-mono-cyrillic-wght-normal.woff2",
		"geist-mono-latin-wght-normal.woff2",
	} {
		t.Run(name, func(t *testing.T) {
			for _, method := range []string{http.MethodGet, http.MethodHead} {
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, httptest.NewRequest(method, "/fonts/"+name, nil))
				if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "font/woff2" {
					t.Fatalf("%s: status %d, content type %q", method, rec.Code, rec.Header().Get("Content-Type"))
				}
				data := rec.Body.Bytes()
				if method == http.MethodHead {
					if len(data) != 0 {
						t.Fatal("HEAD returned a body")
					}
					continue
				}
				if len(data) < 48 || string(data[:4]) != "wOF2" || int(binary.BigEndian.Uint32(data[8:12])) != len(data) {
					t.Fatal("font response is not a complete WOFF2 file")
				}
			}
		})
	}
	for _, name := range []string{"geist-LICENSE.txt", "geist-mono-LICENSE.txt", "fonts-NOTICE.txt", "miboard-NOTICE.txt"} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/licenses/"+name, nil))
			if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "text/plain; charset=utf-8" || !strings.Contains(rec.Body.String(), "License") {
				t.Fatalf("missing readable license: status %d, content type %q", rec.Code, rec.Header().Get("Content-Type"))
			}
		})
	}
	for _, path := range []string{
		"/fonts/", "/fonts/missing.woff2", "/licenses/missing.txt", "/embed.go",
		"/fonts/%2e%2e/embed.go", "/fonts/%2e%2e/%2e%2e/data/admin-password",
		"/fonts/..%5c..%5cdata%5cadmin-password",
	} {
		t.Run(path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
			if rec.Code != http.StatusNotFound {
				t.Fatalf("unexpected static path status: got %d, want 404", rec.Code)
			}
		})
	}
}

func TestEmbeddedThemeScript(t *testing.T) {
	svc, err := service.New(config.Config{DataDir: t.TempDir(), Password: "test-password-12345"})
	if err != nil {
		t.Fatal(err)
	}
	h, err := New(svc)
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(method, "/theme.js", nil))
		if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "text/javascript; charset=utf-8" {
			t.Fatalf("%s: status %d, content type %q", method, rec.Code, rec.Header().Get("Content-Type"))
		}
		if method == http.MethodHead {
			if rec.Body.Len() != 0 {
				t.Fatal("HEAD returned a body")
			}
		} else if !strings.Contains(rec.Body.String(), "window.MIRulesetsTheme") {
			t.Fatal("theme bootstrap is missing from the response")
		}
		if !strings.Contains(rec.Header().Get("Content-Security-Policy"), "script-src 'self';") {
			t.Fatal("theme bootstrap changed the script security policy")
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/theme_test.cjs", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("test file is exposed: got %d, want 404", rec.Code)
	}
}
