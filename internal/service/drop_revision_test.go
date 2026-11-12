package service

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/blagodaren/mirulesets/internal/config"
	"github.com/blagodaren/mirulesets/internal/model"
)

func TestDropGuardAppliesOnlyToPublishedRevision(t *testing.T) {
	for _, edit := range []bool{false, true} {
		t.Run(fmt.Sprintf("edited=%t", edit), func(t *testing.T) {
			lines := make([]string, 100)
			for i := range lines {
				lines[i] = fmt.Sprintf("domain%d.test", i)
			}
			var body atomic.Value
			body.Store(strings.Join(lines, "\n"))
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = fmt.Fprint(w, body.Load().(string)) }))
			defer upstream.Close()
			s, err := New(config.Config{DataDir: t.TempDir(), AllowPrivateSources: true})
			if err != nil {
				t.Fatal(err)
			}
			r, err := s.Save(model.Ruleset{ID: "drop", Name: "Drop", Behavior: "domain", IntervalSeconds: 60, Formats: []string{"text"}, Sources: []model.Source{{URL: upstream.URL, Enabled: true}}}, true)
			if err != nil {
				t.Fatal(err)
			}
			r, err = s.Build(context.Background(), r.ID)
			if err != nil {
				t.Fatal(err)
			}
			generation := r.LastBuild.Generation
			if edit {
				r.Sources = nil
				r.CustomRules = lines[:10]
				r, err = s.Save(r, false)
				if err != nil {
					t.Fatal(err)
				}
			} else {
				body.Store(strings.Join(lines[:10], "\n"))
			}
			r, err = s.Build(context.Background(), r.ID)
			if edit {
				if err != nil {
					t.Fatal(err)
				}
				if r.LastBuild.RuleCount != 10 || r.LastBuild.Added != 0 || r.LastBuild.Removed != 90 {
					t.Fatalf("manual edit diff: %+v", r.LastBuild)
				}
			} else {
				if err == nil || !strings.Contains(err.Error(), "публикация заблокирована") {
					t.Fatalf("upstream loss accepted: %v", err)
				}
				current, _ := s.Store.Get(r.ID)
				if current.LastBuild.Generation != generation {
					t.Fatal("guard changed publication")
				}
			}
		})
	}
}
