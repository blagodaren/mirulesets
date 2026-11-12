package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/blagodaren/mirulesets/internal/config"
	"github.com/blagodaren/mirulesets/internal/model"
	"github.com/blagodaren/mirulesets/internal/service"
	"github.com/blagodaren/mirulesets/internal/storage"
	"github.com/blagodaren/mirulesets/internal/version"
)

func TestMetricsBuildFailuresAndAuthentication(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer upstream.Close()
	token := strings.Repeat("x", 32)
	svc, err := service.New(config.Config{DataDir: t.TempDir(), Password: "test-password-12345", APIToken: token, AllowPrivateSources: true})
	if err != nil {
		t.Fatal(err)
	}
	r, err := svc.Save(model.Ruleset{ID: "demo", Name: "Demo", Behavior: "domain", CustomRules: []string{"example.com"}, IntervalSeconds: 60, Formats: []string{"text"}}, true)
	if err != nil {
		t.Fatal(err)
	}
	h, err := New(svc)
	if err != nil {
		t.Fatal(err)
	}
	scrape := func(auth string, wantStatus int) string {
		t.Helper()
		req := httptest.NewRequest("GET", "/metrics", nil)
		if auth != "" {
			req.Header.Set("Authorization", "Bearer "+auth)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != wantStatus {
			t.Fatalf("metrics status %d: %s", rec.Code, rec.Body.String())
		}
		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("metrics must not be cached")
		}
		if wantStatus == 200 && rec.Header().Get("Content-Type") != "text/plain; version=0.0.4; charset=utf-8" {
			t.Fatal("metrics content type")
		}
		return rec.Body.String()
	}
	scrape("", 401)
	scrape("wrong", 401)
	initial := scrape(token, 200)
	assertMetric(t, initial, "mirulesets_last_success_timestamp_seconds", "demo", 0)
	assertMetric(t, initial, "mirulesets_rules", "demo", 0)
	assertMetric(t, initial, "mirulesets_build_errors_total", "demo", 0)
	r, err = svc.Build(context.Background(), r.ID)
	if err != nil {
		t.Fatal(err)
	}
	successTime := metricValue(t, scrape(token, 200), "mirulesets_last_success_timestamp_seconds", "demo")
	if successTime <= 0 {
		t.Fatal("successful publication timestamp missing")
	}
	r.Sources = []model.Source{{URL: upstream.URL, Enabled: true, Behavior: "domain", Format: "text"}}
	r, err = svc.Save(r, false)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := svc.Build(context.Background(), r.ID); err == nil {
			t.Fatal("expected upstream failure")
		}
	}
	_, _ = svc.Build(context.Background(), "missing")
	failed := scrape(token, 200)
	assertMetric(t, failed, "mirulesets_rules", "demo", 1)
	assertMetric(t, failed, "mirulesets_build_errors_total", "demo", 2)
	assertMetric(t, failed, "mirulesets_last_success_timestamp_seconds", "demo", successTime)
	if metricValue(t, failed, "mirulesets_build_duration_seconds", "demo") <= 0 {
		t.Fatal("last failed build duration missing")
	}
	if strings.Contains(failed, `ruleset="missing"`) {
		t.Fatal("unknown ruleset created a metric series")
	}
	if err := svc.Delete(r.ID); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(scrape(token, 200), `ruleset="demo"`) {
		t.Fatal("deleted ruleset retained a metric series")
	}
}

func TestMetricsCountsPartialS3Failure(t *testing.T) {
	s3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "<Error><Code>AccessDenied</Code><Message>denied</Message></Error>")
	}))
	defer s3.Close()
	svc, err := service.New(config.Config{DataDir: t.TempDir(), S3: storage.Config{Endpoint: s3.URL, Region: "us-east-1", Bucket: "rulesets", AccessKey: "test-access", SecretKey: "test-secret", PathStyle: true}})
	if err != nil {
		t.Fatal(err)
	}
	r, err := svc.Save(model.Ruleset{ID: "s3-test", Name: "S3", Behavior: "domain", CustomRules: []string{"example.com"}, IntervalSeconds: 60, Formats: []string{"text"}}, true)
	if err != nil {
		t.Fatal(err)
	}
	r, err = svc.Build(context.Background(), r.ID)
	if err != nil || r.LastBuild == nil || r.LastError == "" {
		t.Fatalf("expected local success and S3 failure: %+v, %v", r, err)
	}
	got := svc.BuildMetrics()
	if len(got) != 1 || got[0].ErrorsTotal != 1 || got[0].RuleCount != 1 || got[0].LastSuccessTime.IsZero() {
		t.Fatalf("partial S3 failure metrics: %+v", got)
	}
}

func TestMetricLabelEscaping(t *testing.T) {
	if got := metricLabel("a\\b\n\"c"); got != `a\\b\n\"c` {
		t.Fatalf("label escaping: %q", got)
	}
}

func TestSystemUsesBuildVersion(t *testing.T) {
	previous := version.Version
	version.Version = "test-build"
	t.Cleanup(func() { version.Version = previous })
	s := &Server{svc: &service.Service{}}
	if got := s.system()["version"]; got != "test-build" {
		t.Fatalf("API version: %v", got)
	}
}

func metricValue(t *testing.T, body, name, id string) float64 {
	t.Helper()
	prefix := name + `{ruleset="` + id + `"} `
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, prefix) {
			v, err := strconv.ParseFloat(strings.TrimPrefix(line, prefix), 64)
			if err != nil {
				t.Fatal(err)
			}
			return v
		}
	}
	t.Fatalf("missing metric %s for %s in:\n%s", name, id, body)
	return 0
}

func assertMetric(t *testing.T, body, name, id string, want float64) {
	t.Helper()
	if got := metricValue(t, body, name, id); got != want {
		t.Fatalf("%s{%s}: got %g, want %g", name, id, got, want)
	}
}
