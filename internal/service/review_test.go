package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blagodaren/mirulesets/internal/config"
	"github.com/blagodaren/mirulesets/internal/model"
	"github.com/blagodaren/mirulesets/internal/storage"
)

func reviewBuild(t *testing.T, s *Service) model.Ruleset {
	t.Helper()
	r, err := s.Save(model.Ruleset{ID: "review", Name: "Review", Behavior: "domain", IntervalSeconds: 60, Formats: []string{"text"}, CustomRules: []string{"a.example", "b.example", "c.example", "d.example"}}, true)
	if err != nil {
		t.Fatal(err)
	}
	r, err = s.Build(context.Background(), r.ID)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestReviewCanonicalIntegrity(t *testing.T) {
	s, err := New(config.Config{DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	r := reviewBuild(t, s)
	path := filepath.Join(s.Config.DataDir, "artifacts", r.ID, r.LastBuild.Generation, "canonical.json")
	if err := os.WriteFile(path, []byte(`["evil.example","b.example","c.example","d.example"]`), 0600); err != nil {
		t.Fatal(err)
	}
	lines, err := s.generationRules(r.ID, r.LastBuild)
	if err == nil && len(lines) > 0 && lines[0] == "evil.example" {
		t.Fatal("unverified canonical data replaced published artifact semantics")
	}
}

func TestReviewLegacyBehaviorChange(t *testing.T) {
	s, err := New(config.Config{DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	r := reviewBuild(t, s)
	dir := filepath.Join(s.Config.DataDir, "artifacts", r.ID, r.LastBuild.Generation)
	for _, name := range []string{"canonical.json", "build.json"} {
		if err := os.Remove(filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Store.Update(func(st *model.State) error { st.Rulesets[0].LastBuild.Behavior = ""; return nil }); err != nil {
		t.Fatal(err)
	}
	r, _ = s.Store.Get(r.ID)
	r.Behavior = "classical"
	r.CustomRules = []string{"DOMAIN,a.example", "DOMAIN,b.example", "DOMAIN,c.example", "DOMAIN,d.example"}
	r, err = s.Save(r, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Build(context.Background(), r.ID); err != nil {
		t.Fatalf("legacy publication blocked behavior change: %v", err)
	}
}

func reviewS3Config(url string) storage.Config {
	return storage.Config{Endpoint: url, Bucket: "review-bucket", AccessKey: "access", SecretKey: "secret", Region: "us-east-1", Prefix: "rules", PathStyle: true}
}

func TestReviewDropGuardPrecedesS3(t *testing.T) {
	var puts atomic.Int32
	var body atomic.Value
	body.Store("a.example\nb.example\nc.example\nd.example\n")
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && r.URL.Path == "/source" {
			_, _ = w.Write([]byte(body.Load().(string)))
			return
		}
		if r.Method == "PUT" {
			puts.Add(1)
		}
		w.Header().Set("ETag", "\"test\"")
	}))
	defer endpoint.Close()
	s, err := New(config.Config{DataDir: t.TempDir(), AllowPrivateSources: true, S3: reviewS3Config(endpoint.URL)})
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.Save(model.Ruleset{ID: "review", Name: "Review", Behavior: "domain", IntervalSeconds: 60, Formats: []string{"text"}, Sources: []model.Source{{URL: endpoint.URL + "/source", Enabled: true}}}, true)
	if err != nil {
		t.Fatal(err)
	}
	r, err = s.Build(context.Background(), r.ID)
	if err != nil {
		t.Fatal(err)
	}
	generation := r.LastBuild.Generation
	body.Store("a.example\n")
	if _, err = s.Build(context.Background(), r.ID); err == nil {
		t.Fatal("drop was not rejected")
	}
	current, _ := s.Store.Get(r.ID)
	if puts.Load() != 1 || current.LastBuild.Generation != generation {
		t.Fatalf("guard ran after publication: puts=%d generation=%s", puts.Load(), current.LastBuild.Generation)
	}
}

func TestReviewS3CleanupBoundToOriginalTarget(t *testing.T) {
	oldEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "DELETE" {
			w.WriteHeader(403)
			return
		}
		w.Header().Set("ETag", "\"test\"")
	}))
	defer oldEndpoint.Close()
	var wrongDeletes atomic.Int32
	newEndpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "DELETE" {
			wrongDeletes.Add(1)
		}
		w.WriteHeader(204)
	}))
	defer newEndpoint.Close()
	s, err := New(config.Config{DataDir: t.TempDir(), S3: reviewS3Config(oldEndpoint.URL)})
	if err != nil {
		t.Fatal(err)
	}
	r := reviewBuild(t, s)
	if err := s.Delete(r.ID); err == nil {
		t.Fatal("failed deletion must remain pending")
	}
	s.Config.S3 = reviewS3Config(newEndpoint.URL)
	s.S3, err = storage.NewS3(s.Config.S3)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.cleanupS3Deletes(context.Background())
	if wrongDeletes.Load() != 0 {
		t.Fatalf("cleanup deleted %d objects from a different S3 target", wrongDeletes.Load())
	}
}

func TestReviewNoopImportPreservesSourceStatus(t *testing.T) {
	s, err := New(config.Config{DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	r := reviewBuild(t, s)
	r.Sources = []model.Source{{URL: "https://example.com/list", Name: "Source", Enabled: false}}
	r, err = s.Save(r, false)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Store.Update(func(st *model.State) error {
		st.Rulesets[0].Sources[0].Status = &model.SourceStatus{HTTPStatus: 304, RuleCount: 7, CheckedAt: time.Now().UTC()}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	exported := s.ExportConfig()
	if err = s.ImportConfig(exported); err != nil {
		t.Fatal(err)
	}
	after, _ := s.Store.Get(r.ID)
	if after.Revision != r.Revision {
		t.Fatal("no-op import changed revision")
	}
	if after.Sources[0].Status == nil || after.Sources[0].Status.HTTPStatus != 304 {
		t.Fatal("no-op import erased runtime source status")
	}
}

func TestReviewIdenticalBinaryDoesNotReuseDifferentCanonical(t *testing.T) {
	for _, format := range []string{"mrs", "srs"} {
		t.Run(format, func(t *testing.T) {
			s, err := New(config.Config{DataDir: t.TempDir()})
			if err != nil {
				t.Fatal(err)
			}
			r, err := s.Save(model.Ruleset{ID: "cidrs", Name: "CIDRs", Behavior: "ipcidr", IntervalSeconds: 60, Formats: []string{format}, CustomRules: []string{"192.0.2.0/24"}}, true)
			if err != nil {
				t.Fatal(err)
			}
			r, err = s.Build(context.Background(), r.ID)
			if err != nil {
				t.Fatal(err)
			}
			first := r.LastBuild.Generation
			r.CustomRules = append(r.CustomRules, "192.0.2.0/25", "192.0.2.128/25")
			r, err = s.Save(r, false)
			if err != nil {
				t.Fatal(err)
			}
			r, err = s.Build(context.Background(), r.ID)
			if err != nil {
				t.Fatal(err)
			}
			if r.LastBuild.Generation == first {
				t.Errorf("new canonical list reused immutable generation %s", first)
			}
			if _, err = s.generationRules(r.ID, r.LastBuild); err != nil {
				t.Errorf("published canonical snapshot is invalid: %v", err)
			}
			if _, err = s.Build(context.Background(), r.ID); err != nil {
				t.Errorf("third build blocked: %v", err)
			}
		})
	}
}
