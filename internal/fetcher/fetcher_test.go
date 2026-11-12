package fetcher

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
)

func TestBlocksInternalNetworks(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "10.0.0.1", "192.168.0.1", "169.254.169.254", "100.100.100.200", "::1", "::ffff:127.0.0.1", "fc00::1", "64:ff9b::a00:1"} {
		if AllowedIP(netip.MustParseAddr(ip)) {
			t.Errorf("allowed %s", ip)
		}
	}
	if !AllowedIP(netip.MustParseAddr("1.1.1.1")) {
		t.Fatal("public IP blocked")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("request reached private endpoint") }))
	defer srv.Close()
	if _, err := New(false).Get(context.Background(), srv.URL); err == nil {
		t.Fatal("private source accepted")
	}
}
func TestConditionalFetchAndRedirectPolicy(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(304)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		_, _ = w.Write([]byte("+.example.com\n"))
	}))
	defer srv.Close()
	f := New(true)
	a, err := f.Get(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	b, err := f.Get(context.Background(), srv.URL)
	if err != nil || string(a) != string(b) || n.Load() != 2 {
		t.Fatalf("cache: %q %q %v", a, b, err)
	}
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "file:///etc/passwd", 302) }))
	defer redir.Close()
	if _, err = f.Get(context.Background(), redir.URL); err == nil {
		t.Fatal("invalid redirect accepted")
	}
}

func TestScopedPrivateSourceException(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("example.com\n")) }))
	defer srv.Close()
	f := New(false, netip.MustParsePrefix("127.0.0.1/32"))
	if _, err := f.Get(context.Background(), srv.URL); err != nil {
		t.Fatal(err)
	}
	f = New(false, netip.MustParsePrefix("198.18.0.0/15"))
	if _, err := f.Get(context.Background(), srv.URL); err == nil {
		t.Fatal("exception leaked to another network")
	}
}
