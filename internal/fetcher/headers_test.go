package fetcher

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestHeaderCacheIsolatesCredentialsAndReportsStatus(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		token := r.Header.Get("Authorization")
		if r.Header.Get("If-None-Match") == token {
			w.WriteHeader(304)
			return
		}
		if r.Header.Get("If-None-Match") != "" {
			t.Error("conditional credentials leaked between cache entries")
		}
		w.Header().Set("ETag", token)
		_, _ = w.Write([]byte(token))
	}))
	defer srv.Close()
	f := New(true)
	for _, token := range []string{"alpha", "beta", "alpha"} {
		result, err := f.GetWithHeaders(context.Background(), srv.URL, map[string]string{"Authorization": token})
		if err != nil || string(result.Body) != token {
			t.Fatalf("body=%q err=%v", result.Body, err)
		}
		want := 200
		if calls.Load() == 3 {
			want = 304
		}
		if result.HTTPStatus != want {
			t.Fatalf("status=%d want=%d", result.HTTPStatus, want)
		}
	}
}

func TestCrossOriginRedirectStripsAllCustomHeaders(t *testing.T) {
	var originalURL string
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" || r.Header.Get("X-Api-Key") != "" || r.Header.Get("Cookie") != "" {
			t.Error("credentials leaked to redirect origin")
		}
		http.Redirect(w, r, originalURL+"/returned", 302)
	}))
	defer destination.Close()
	original := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/returned" {
			if r.Header.Get("X-Api-Key") != "" {
				t.Error("credentials restored after cross-origin redirect")
			}
			_, _ = w.Write([]byte("ok"))
			return
		}
		if r.Header.Get("X-Api-Key") != "private" {
			t.Error("initial credentials missing")
		}
		http.Redirect(w, r, destination.URL, 302)
	}))
	defer original.Close()
	originalURL = original.URL
	result, err := New(true).GetWithHeaders(context.Background(), original.URL, map[string]string{"X-Api-Key": "private", "Authorization": "Bearer private", "Cookie": "session=private"})
	if err != nil || string(result.Body) != "ok" {
		t.Fatalf("%q: %v", result.Body, err)
	}
}

func TestRejectsUnsafeHeadersWithoutSecretInErrors(t *testing.T) {
	for _, headers := range []map[string]string{
		{"Authorization": "private\r\nHost: evil"}, {"Host": "private"}, {"If-None-Match": "private"}, {"X Secret": "private"}, {"X-Key": "private", "x-key": "private"},
	} {
		err := ValidateHeaders(headers)
		if err == nil || strings.Contains(err.Error(), "private") {
			t.Fatalf("unsafe or leaking validation: %v", err)
		}
	}
}
