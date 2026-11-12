package server

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/blagodaren/mirulesets/internal/config"
	"github.com/blagodaren/mirulesets/internal/model"
	"github.com/blagodaren/mirulesets/internal/rules"
	"github.com/blagodaren/mirulesets/internal/service"
)

func TestAuthenticatedWorkflow(t *testing.T) {
	svc, err := service.New(config.Config{DataDir: t.TempDir(), Password: "test-password-12345"})
	if err != nil {
		t.Fatal(err)
	}
	h, err := New(svc)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}
	request := func(method, path string, body any, csrf bool) *http.Response {
		t.Helper()
		var b []byte
		if body != nil {
			b, _ = json.Marshal(body)
		}
		req, _ := http.NewRequest(method, srv.URL+path, bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		if csrf {
			req.Header.Set("X-Requested-With", "MIRulesets")
		}
		resp, e := client.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		return resp
	}
	check := func(resp *http.Response, status int) {
		t.Helper()
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != status {
			t.Fatalf("expected %d, got %d: %s", status, resp.StatusCode, b)
		}
	}
	check(request("GET", "/api/overview", nil, false), 401)
	check(request("POST", "/api/login", map[string]string{"password": "test-password-12345"}, false), 403)
	check(request("POST", "/api/login", map[string]string{"password": "wrong"}, true), 401)
	check(request("POST", "/api/login", map[string]string{"password": "test-password-12345"}, true), 200)
	check(request("GET", "/api/overview", nil, false), 200)
	set := model.Ruleset{ID: "demo", Name: "Рабочий набор", Behavior: "domain", CustomRules: []string{"+.example.com", "test.example.org"}, IntervalSeconds: 3600, Formats: []string{"mrs", "yaml", "text"}, Enabled: true}
	check(request("POST", "/api/rulesets", set, false), 403)
	check(request("POST", "/api/rulesets", set, true), 201)
	check(request("POST", "/api/rulesets/demo/build", nil, true), 200)
	resp := request("GET", "/rules/demo.mrs", nil, false)
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
	lines, err := rules.Parse(data, "mrs", "domain")
	if err != nil || len(lines) != 2 {
		t.Fatalf("invalid download: %v %v", lines, err)
	}
	etag := resp.Header.Get("ETag")
	req, _ := http.NewRequest("GET", srv.URL+"/rules/demo.mrs", nil)
	req.Header.Set("If-None-Match", etag)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	check(resp, 304)
	check(request("GET", "/api/rulesets/demo/snippet?format=mrs", nil, false), 200)
	check(request("GET", "/rules/unknown.mrs", nil, false), 404)
	check(request("POST", "/api/logout", nil, true), 200)
	check(request("GET", "/api/overview", nil, false), 401)
	check(request("GET", "/rules/demo.yaml", nil, false), 200)
	check(request("GET", "/app.js", nil, false), 200)
}

func TestCrossOriginLogin(t *testing.T) {
	svc, err := service.New(config.Config{DataDir: t.TempDir(), Password: "test-password-12345", APIToken: strings.Repeat("x", 32)})
	if err != nil {
		t.Fatal(err)
	}
	h, err := New(svc)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "http://localhost/api/login", strings.NewReader(`{"password":"test-password-12345"}`))
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("X-Requested-With", "MIRulesets")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Fatal("cross origin login accepted")
	}
}

func TestTrustedProxyChain(t *testing.T) {
	s := &Server{svc: &service.Service{Config: config.Config{TrustedProxies: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}}}}
	r := httptest.NewRequest("GET", "http://localhost/api/session", nil)
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("X-Forwarded-For", "1.1.1.1, 8.8.8.8")
	if s.clientIP(r) != "8.8.8.8" {
		t.Fatal("trusted chain did not select real client")
	}
	r.RemoteAddr = "9.9.9.9:1234"
	if s.clientIP(r) != "9.9.9.9" {
		t.Fatal("untrusted peer spoofed client")
	}
}
