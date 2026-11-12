package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/blagodaren/mirulesets/internal/config"
	"github.com/blagodaren/mirulesets/internal/model"
	"github.com/blagodaren/mirulesets/internal/service"
)

func featureServer(t *testing.T) (*service.Service, http.Handler, func(string, string, any, int) *httptest.ResponseRecorder) {
	t.Helper()
	token := strings.Repeat("feature-token", 3)
	svc, err := service.New(config.Config{DataDir: t.TempDir(), Password: "test-password-12345", APIToken: token})
	if err != nil {
		t.Fatal(err)
	}
	h, err := New(svc)
	if err != nil {
		t.Fatal(err)
	}
	call := func(method, path string, body any, status int) *httptest.ResponseRecorder {
		t.Helper()
		var data []byte
		if body != nil {
			data, _ = json.Marshal(body)
		}
		req := httptest.NewRequest(method, path, bytes.NewReader(data))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != status {
			t.Fatalf("%s %s: got %d want %d: %s", method, path, rec.Code, status, rec.Body.String())
		}
		return rec
	}
	return svc, h, call
}

func featureSet(id string) model.Ruleset {
	return model.Ruleset{ID: id, Name: id, Behavior: "domain", CustomRules: []string{"+.example.com"}, IntervalSeconds: 3600, Formats: []string{"yaml", "text"}, Tags: []string{"work"}}
}

func TestAPIRedactsHeadersAndConfigurationRoundTrip(t *testing.T) {
	svc, _, call := featureServer(t)
	r := featureSet("private")
	r.Sources = []model.Source{{Name: "private source", URL: "https://example.org/list", Format: "text", Behavior: "domain", Headers: map[string]string{"Authorization": "Bearer secret-never-return"}}}
	create := call("POST", "/api/rulesets", r, 201)
	if strings.Contains(create.Body.String(), "secret-never-return") {
		t.Fatal("create leaked source credentials")
	}
	for _, path := range []string{"/api/rulesets/private", "/api/rulesets", "/api/overview", "/api/config"} {
		res := call("GET", path, nil, 200)
		if strings.Contains(res.Body.String(), "secret-never-return") || strings.Contains(res.Body.String(), `"headers":`) {
			t.Fatalf("credentials leaked in %s: %s", path, res.Body.String())
		}
	}
	for _, action := range []string{"build", "clone"} {
		var body any
		if action == "clone" {
			body = map[string]string{"id": "copy", "name": "Copy"}
		}
		res := call("POST", "/api/rulesets/private/"+action, body, 200)
		if strings.Contains(res.Body.String(), "secret-never-return") {
			t.Fatalf("%s leaked credentials", action)
		}
	}
	copySet, _ := svc.Store.Get("copy")
	if copySet.Sources[0].Headers["Authorization"] != "Bearer secret-never-return" || copySet.LastBuild != nil {
		t.Fatal("clone must preserve server credentials and omit publication")
	}
	var exported model.State
	res := call("GET", "/api/config", nil, 200)
	if err := json.Unmarshal(res.Body.Bytes(), &exported); err != nil {
		t.Fatal(err)
	}
	if exported.Rulesets[0].LastBuild != nil {
		t.Fatal("export contains runtime publication")
	}
	exported.Rulesets = exported.Rulesets[:1]
	exported.Rulesets[0].Name = "Updated from import"
	call("POST", "/api/config", exported, 200)
	stored, _ := svc.Store.Get("private")
	if stored.Name != "Updated from import" || stored.LastBuild == nil || stored.Sources[0].Headers["Authorization"] != "Bearer secret-never-return" {
		t.Fatal("config round trip lost publication or source headers")
	}
	if _, ok := svc.Store.Get("copy"); !ok {
		t.Fatal("merge removed an omitted ruleset")
	}
	call("POST", "/api/config", exported, 409)
}

func TestAllSnippetPolicyAndLookup(t *testing.T) {
	svc, _, call := featureServer(t)
	for _, id := range []string{"ready", "pending"} {
		if _, err := svc.Save(featureSet(id), true); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := svc.Build(context.Background(), "ready"); err != nil {
		t.Fatal(err)
	}
	res := call("GET", "/api/snippet?policy=DIRECT", nil, 200)
	var snippet struct {
		YAML     string   `json:"yaml"`
		Included int      `json:"included"`
		Skipped  []string `json:"skipped"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &snippet); err != nil {
		t.Fatal(err)
	}
	if snippet.Included != 1 || len(snippet.Skipped) != 1 || snippet.Skipped[0] != "pending" || !strings.Contains(snippet.YAML, "RULE-SET,ready,DIRECT") {
		t.Fatalf("bad global snippet: %+v", snippet)
	}
	call("GET", "/api/snippet?policy=BAD%2CINJECT", nil, 400)
	call("GET", "/api/snippet?policy=BAD%0AINJECT", nil, 400)
	lookup := call("GET", "/api/lookup?query=sub.example.com", nil, 200)
	if !strings.Contains(lookup.Body.String(), `"rulesetId":"ready"`) || strings.Contains(lookup.Body.String(), `"rulesetId":"pending"`) {
		t.Fatalf("lookup must use publications: %s", lookup.Body.String())
	}
	call("GET", "/api/lookup?query=not+a+domain", nil, 400)
}

func TestDownloadMetricsExcludeConditionalAndHead(t *testing.T) {
	svc, h, call := featureServer(t)
	if _, err := svc.Save(featureSet("counted"), true); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Build(context.Background(), "counted"); err != nil {
		t.Fatal(err)
	}
	first := call("GET", "/rules/counted.txt", nil, 200)
	call("HEAD", "/rules/counted.txt", nil, 200)
	req := httptest.NewRequest("GET", "/rules/counted.txt", nil)
	req.Header.Set("If-None-Match", first.Header().Get("ETag"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 304 {
		t.Fatalf("conditional download: %d", rec.Code)
	}
	req = httptest.NewRequest("GET", "/rules/counted.txt", nil)
	req.Header.Set("Range", "bytes=0-3")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 206 {
		t.Fatalf("range download: %d", rec.Code)
	}
	call("GET", "/rules/missing.txt", nil, 404)
	assertMetric(t, call("GET", "/metrics", nil, 200).Body.String(), "mirulesets_downloads_total", "counted", 2)
	overview := call("GET", "/api/overview", nil, 200)
	if !strings.Contains(overview.Body.String(), `"downloads":{"counted":2}`) {
		t.Fatalf("downloads missing in overview: %s", overview.Body.String())
	}
}

func TestRollbackAndNewArtifactFormatsAPI(t *testing.T) {
	svc, _, call := featureServer(t)
	r := featureSet("history")
	r.Formats = []string{"text", "singbox", "srs"}
	r, err := svc.Save(r, true)
	if err != nil {
		t.Fatal(err)
	}
	r, err = svc.Build(context.Background(), r.ID)
	if err != nil {
		t.Fatal(err)
	}
	old := call("GET", "/rules/history.txt", nil, 200).Body.String()
	jsonArtifact := call("GET", "/rules/history.json", nil, 200)
	if !strings.HasPrefix(jsonArtifact.Header().Get("Content-Type"), "application/json") || !json.Valid(jsonArtifact.Body.Bytes()) {
		t.Fatal("sing-box JSON artifact is not JSON")
	}
	call("GET", "/rules/history.srs", nil, 200)
	call("GET", "/api/rulesets/history/snippet?format=singbox", nil, 400)
	r.CustomRules = append(r.CustomRules, "new.example.net")
	r, err = svc.Save(r, false)
	if err != nil {
		t.Fatal(err)
	}
	call("POST", "/api/rulesets/history/build", nil, 200)
	call("POST", "/api/rulesets/history/rollback", nil, 200)
	if got := call("GET", "/rules/history.txt", nil, 200).Body.String(); got != old {
		t.Fatalf("rollback did not switch public contents: %s", got)
	}
	call("POST", "/api/rulesets/history/retry-s3", nil, 400)
}
