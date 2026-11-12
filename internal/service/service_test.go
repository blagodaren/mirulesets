package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/blagodaren/mirulesets/internal/config"
	"github.com/blagodaren/mirulesets/internal/model"
)

func TestBuildLastGoodPersistenceAndExclusions(t *testing.T) {
	var broken atomic.Bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if broken.Load() {
			w.WriteHeader(503)
			return
		}
		_, _ = w.Write([]byte("+.example.com\nremove.test\n+.example.com\n"))
	}))
	defer upstream.Close()
	c := config.Config{DataDir: t.TempDir(), AllowPrivateSources: true}
	s, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	r := model.Ruleset{ID: "test", Name: "Тест", Behavior: "domain", Sources: []model.Source{{URL: upstream.URL, Format: "auto", Behavior: "domain", Enabled: true}}, CustomRules: []string{"custom.test"}, ExcludeRules: []string{"remove.test"}, IntervalSeconds: 60, Formats: []string{"text", "yaml", "mrs"}, Enabled: true}
	r, err = s.Save(r, true)
	if err != nil {
		t.Fatal(err)
	}
	r, err = s.Build(context.Background(), r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if r.LastBuild.RuleCount != 2 || len(r.LastBuild.Files) != 3 {
		t.Fatalf("build: %+v", r.LastBuild)
	}
	b, err := os.ReadFile(filepath.Join(c.DataDir, "artifacts", r.ID, r.LastBuild.Generation, "rules.txt"))
	if err != nil || string(b) != "+.example.com\ncustom.test\n" {
		t.Fatalf("output %q: %v", b, err)
	}
	oldGen := r.LastBuild.Generation
	broken.Store(true)
	if _, err = s.Build(context.Background(), r.ID); err == nil {
		t.Fatal("failed source silently accepted")
	}
	got, _ := s.Store.Get(r.ID)
	if got.LastBuild.Generation != oldGen || got.LastError == "" {
		t.Fatal("last known good not preserved")
	}
	reopened, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := reopened.Store.Get(r.ID)
	if !ok || got.LastBuild.Generation != oldGen {
		t.Fatal("state did not persist")
	}
	r.Name = "Изменено"
	r, err = s.Save(r, false)
	if err != nil {
		t.Fatal(err)
	}
	r.Revision--
	if _, err = s.Save(r, false); err != ErrConflict {
		t.Fatalf("lost update was accepted: %v", err)
	}
}

func TestRejectsInvalidDefinitions(t *testing.T) {
	r := model.Ruleset{ID: "valid", Name: "Valid", Behavior: "classical", IntervalSeconds: 60, Formats: []string{"mrs"}}
	if Validate(&r) == nil {
		t.Fatal("classical MRS accepted")
	}
	r.Behavior = "domain"
	r.ID = "../escape"
	if Validate(&r) == nil {
		t.Fatal("path traversal accepted")
	}
}
