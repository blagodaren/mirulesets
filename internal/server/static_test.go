package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/blagodaren/mirulesets/internal/config"
	"github.com/blagodaren/mirulesets/internal/service"
)

func TestStaticRevalidation(t *testing.T) {
	svc, err := service.New(config.Config{DataDir: t.TempDir(), Password: "test-password-12345"})
	if err != nil {
		t.Fatal(err)
	}
	h, err := New(svc)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		"/", "/index.html", "/app.js", "/theme.js", "/styles.css", "/favicon.svg",
		"/fonts/geist-cyrillic-wght-normal.woff2", "/fonts/geist-latin-wght-normal.woff2",
		"/fonts/geist-mono-cyrillic-wght-normal.woff2", "/fonts/geist-mono-latin-wght-normal.woff2",
		"/licenses/geist-LICENSE.txt", "/licenses/geist-mono-LICENSE.txt",
		"/licenses/fonts-NOTICE.txt", "/licenses/miboard-NOTICE.txt",
	} {
		t.Run(path, func(t *testing.T) {
			first := httptest.NewRecorder()
			h.ServeHTTP(first, httptest.NewRequest(http.MethodGet, path, nil))
			if first.Code != http.StatusOK || first.Body.Len() == 0 {
				t.Fatalf("initial GET: status %d, body length %d", first.Code, first.Body.Len())
			}
			etag := first.Header().Get("ETag")
			if want := fmt.Sprintf(`"%x"`, sha256.Sum256(first.Body.Bytes())); etag != want {
				t.Fatalf("ETag = %q, want content hash %q", etag, want)
			}
			for _, method := range []string{http.MethodGet, http.MethodHead} {
				for _, tc := range []struct {
					name   string
					etag   string
					status int
				}{
					{"unconditional", "", http.StatusOK},
					{"unchanged", etag, http.StatusNotModified},
					{"weak", "W/" + etag, http.StatusNotModified},
					{"list", `"old", W/` + etag + `, "other"`, http.StatusNotModified},
					{"wildcard", "*", http.StatusNotModified},
					{"changed", `"old"`, http.StatusOK},
				} {
					t.Run(method+"/"+tc.name, func(t *testing.T) {
						req := httptest.NewRequest(method, path, nil)
						if tc.etag != "" {
							req.Header.Set("If-None-Match", tc.etag)
						}
						rec := httptest.NewRecorder()
						h.ServeHTTP(rec, req)
						if rec.Code != tc.status {
							t.Fatalf("status = %d, want %d", rec.Code, tc.status)
						}
						if rec.Header().Get("ETag") != etag || rec.Header().Get("Cache-Control") != "no-cache" {
							t.Fatalf("revalidation headers lost: ETag %q, Cache-Control %q", rec.Header().Get("ETag"), rec.Header().Get("Cache-Control"))
						}
						if rec.Header().Get("Content-Security-Policy") != first.Header().Get("Content-Security-Policy") {
							t.Fatal("revalidation changed the security policy")
						}
						if method == http.MethodHead || tc.status == http.StatusNotModified {
							if rec.Body.Len() != 0 {
								t.Fatalf("unexpected body: %d bytes", rec.Body.Len())
							}
						} else if !bytes.Equal(rec.Body.Bytes(), first.Body.Bytes()) {
							t.Fatal("response does not contain the complete current asset")
						}
						if tc.status == http.StatusOK && rec.Header().Get("Content-Length") != strconv.Itoa(first.Body.Len()) {
							t.Fatalf("Content-Length = %q, want %d", rec.Header().Get("Content-Length"), first.Body.Len())
						}
					})
				}
			}
		})
	}
	for _, path := range []string{"/missing.js", "/embed.go"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("If-None-Match", "*")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound || rec.Header().Get("ETag") != "" {
			t.Fatalf("%s: status %d, ETag %q; want 404 without ETag", path, rec.Code, rec.Header().Get("ETag"))
		}
	}
}

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
