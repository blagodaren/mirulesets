package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blagodaren/mirulesets/internal/config"
	"github.com/blagodaren/mirulesets/internal/model"
	"github.com/blagodaren/mirulesets/internal/storage"
)

func TestRuleDropGuardBoundaryDiffAndRollback(t *testing.T) {
	var body atomic.Value
	body.Store("a.test\nb.test\nc.test\nd.test\n")
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body.Load().(string))) }))
	defer source.Close()
	s, err := New(config.Config{DataDir: t.TempDir(), AllowPrivateSources: true})
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.Save(model.Ruleset{ID: "guard", Name: "Guard", Behavior: "domain", IntervalSeconds: 3600, Enabled: true, Formats: []string{"text", "yaml"}, Sources: []model.Source{{URL: source.URL, Enabled: true}}}, true)
	if err != nil {
		t.Fatal(err)
	}
	r, err = s.Build(context.Background(), r.ID)
	if err != nil {
		t.Fatal(err)
	}
	first := r.LastBuild.Generation
	if r.LastBuild.Added != 4 || r.LastBuild.Removed != 0 {
		t.Fatalf("first diff: %+v", r.LastBuild)
	}
	body.Store("a.test\n")
	if _, err = s.Build(context.Background(), r.ID); err == nil || !strings.Contains(err.Error(), "публикация заблокирована") {
		t.Fatalf("drop accepted: %v", err)
	}
	got, _ := s.Store.Get(r.ID)
	if got.LastBuild.Generation != first || got.Sources[0].Status.RuleCount != 1 {
		t.Fatalf("last-good or source status lost: %+v", got)
	}
	body.Store("a.test\nb.test\n")
	r, err = s.Build(context.Background(), r.ID)
	if err != nil {
		t.Fatal(err)
	}
	second := r.LastBuild.Generation
	if first == second || r.LastBuild.Removed != 2 || r.LastBuild.Added != 0 {
		t.Fatalf("50%% boundary/diff: %+v", r.LastBuild)
	}
	r, err = s.Rollback(context.Background(), r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if r.LastBuild.Generation != first || r.LastBuild.RuleCount != 4 || r.LastBuild.PreviousGeneration != second {
		t.Fatalf("rollback: %+v", r.LastBuild)
	}
	if s.buildDue(r, time.Now()) {
		t.Fatal("scheduler immediately undid rollback")
	}
	reopened, err := New(s.Config)
	if err != nil {
		t.Fatal(err)
	}
	r, _ = reopened.Store.Get(r.ID)
	if reopened.buildDue(r, time.Now()) {
		t.Fatal("rollback pause lost after restart")
	}
	r, err = reopened.Rollback(context.Background(), r.ID)
	if err != nil || r.LastBuild.Generation != second {
		t.Fatalf("redo: %v %+v", err, r.LastBuild)
	}
}

func TestImportAtomicSecretsAndDeclarativeIdempotence(t *testing.T) {
	s, r := retryTestService(t)
	r.Sources = []model.Source{{URL: "https://example.com/rules", Name: "Private", Headers: map[string]string{"Authorization": "Bearer top-secret"}}}
	var err error
	r, err = s.Save(r, false)
	if err != nil {
		t.Fatal(err)
	}
	exported := s.ExportConfig()
	b, _ := json.Marshal(exported)
	if strings.Contains(string(b), "top-secret") {
		t.Fatal("export leaked secret")
	}
	exported.Rulesets[0].Name = "Changed"
	if err = s.ImportConfig(exported); err != nil {
		t.Fatal(err)
	}
	saved, _ := s.Store.Get(r.ID)
	if saved.Sources[0].Headers["Authorization"] != "Bearer top-secret" {
		t.Fatal("import removed existing secret")
	}
	exported = s.ExportConfig()
	exported.Rulesets[0].Name = "Must not commit"
	exported.Rulesets = append(exported.Rulesets, model.Ruleset{ID: "../invalid"})
	if err = s.ImportConfig(exported); err == nil {
		t.Fatal("invalid import accepted")
	}
	saved, _ = s.Store.Get(r.ID)
	if saved.Name != "Changed" {
		t.Fatal("partial import committed")
	}
	cfg := filepath.Join(t.TempDir(), "rulesets.yml")
	content := `version: 1
rulesets:
  - id: declared
    name: Declared
    behavior: domain
    intervalSeconds: 3600
    enabled: true
    formats: [text]
    sources:
      - name: Public
        url: https://example.org/list
        enabled: true
    customRules: [example.org]
`
	if err = os.WriteFile(cfg, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	if err = s.applyConfigFile(cfg); err != nil {
		t.Fatal(err)
	}
	before, _ := s.Store.Get("declared")
	if err = s.applyConfigFile(cfg); err != nil {
		t.Fatal(err)
	}
	after, _ := s.Store.Get("declared")
	if before.Revision != after.Revision || before.Sources[0].ID != after.Sources[0].ID {
		t.Fatal("declarative restart changed unchanged source/revision")
	}
	clone, err := s.Clone(r.ID, "copy", "Copy")
	if err != nil {
		t.Fatal(err)
	}
	if clone.LastBuild != nil || clone.Sources[0].Headers["Authorization"] != "Bearer top-secret" {
		t.Fatal("clone lost configuration or kept publication")
	}
}

func TestRetryOnlyFailedS3FormatsAndDeleteObjects(t *testing.T) {
	var textPuts, yamlPuts, gets, deletes atomic.Int32
	var fail atomic.Bool
	fail.Store(true)
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "PUT":
			if strings.HasSuffix(r.URL.Path, ".txt") {
				textPuts.Add(1)
			} else {
				yamlPuts.Add(1)
				if fail.Load() {
					w.WriteHeader(403)
					return
				}
			}
			w.Header().Set("ETag", "\"etag\"")
		case "DELETE":
			deletes.Add(1)
			w.WriteHeader(204)
		default:
			gets.Add(1)
			w.WriteHeader(500)
		}
	}))
	defer endpoint.Close()
	s, err := New(config.Config{DataDir: t.TempDir(), S3: storage.Config{Endpoint: endpoint.URL, Bucket: "test-bucket", AccessKey: "access", SecretKey: "secret", Region: "us-east-1", PathStyle: true, Prefix: "rules"}})
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.Save(model.Ruleset{ID: "retry", Name: "Retry", Behavior: "domain", IntervalSeconds: 60, Formats: []string{"text", "yaml"}, CustomRules: []string{"example.com"}}, true)
	if err != nil {
		t.Fatal(err)
	}
	r, err = s.Build(context.Background(), r.ID)
	if err != nil {
		t.Fatal(err)
	}
	generation := r.LastBuild.Generation
	if r.LastBuild.S3Published || r.LastError == "" {
		t.Fatal("partial upload not reported")
	}
	fail.Store(false)
	r, err = s.RetryS3(context.Background(), r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if textPuts.Load() != 1 || yamlPuts.Load() != 2 || gets.Load() != 0 || r.LastBuild.Generation != generation || !r.LastBuild.S3Published {
		t.Fatalf("retry rebuilt/refetched successful files: text=%d yaml=%d get=%d", textPuts.Load(), yamlPuts.Load(), gets.Load())
	}
	if err = s.Delete(r.ID); err != nil {
		t.Fatal(err)
	}
	if deletes.Load() != 5 || len(s.Store.PendingS3Deletes()) != 0 {
		t.Fatalf("S3 cleanup: deletes=%d pending=%v", deletes.Load(), s.Store.PendingS3Deletes())
	}
}
