package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blagodaren/mirulesets/internal/config"
	"github.com/blagodaren/mirulesets/internal/service"
)

func TestMetricsTokenIsRestrictedToMonitoring(t *testing.T) {
	apiToken, metricsToken := strings.Repeat("a", 32), strings.Repeat("m", 32)
	svc, err := service.New(config.Config{DataDir: t.TempDir(), Password: "test-password-12345", APIToken: apiToken, MetricsToken: metricsToken})
	if err != nil {
		t.Fatal(err)
	}
	h, err := New(svc)
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, path, token string, want int) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, path, nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Fatalf("%s %s = %d, want %d: %s", method, path, rec.Code, want, rec.Body.String())
		}
		return rec
	}
	request("GET", "/metrics", metricsToken, 200)
	request("HEAD", "/metrics", metricsToken, 200)
	request("GET", "/metrics", apiToken, 200)
	request("GET", "/metrics", "", 401)
	request("GET", "/metrics", strings.Repeat("m", 31)+"x", 401)
	request("GET", "/api/rulesets", apiToken, 200)
	for _, path := range []string{"/api/rulesets", "/api/overview", "/api/system", "/api/config", "/api/snippet", "/api/lookup?query=example.com"} {
		request("GET", path, metricsToken, 401)
	}
	for _, path := range []string{"/api/rulesets", "/api/preview", "/api/config", "/api/logout", "/api/rulesets/test/resume", "/api/rulesets/test/build"} {
		request("POST", path, metricsToken, 401)
	}
	if body := request("GET", "/api/session", metricsToken, 200).Body.String(); !strings.Contains(body, `"authenticated":false`) {
		t.Fatalf("metrics token became a session: %s", body)
	}

	login := httptest.NewRequest("POST", "/api/login", strings.NewReader(`{"password":"test-password-12345"}`))
	login.Header.Set("X-Requested-With", "MIRulesets")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, login)
	if rec.Code != 200 {
		t.Fatalf("session login: %d", rec.Code)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("login cookies: %d", len(cookies))
	}
	for _, path := range []string{"/metrics", "/api/rulesets"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.AddCookie(cookies[0])
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("session %s: %d", path, rec.Code)
		}
	}

	svc.Config.MetricsToken = ""
	request("GET", "/metrics", metricsToken, 401)
	request("GET", "/metrics", apiToken, 200)
}
