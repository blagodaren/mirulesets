package service

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/blagodaren/mirulesets/internal/model"
	"github.com/blagodaren/mirulesets/internal/storage"
)

func heldRuleset(t *testing.T) (*Service, model.Ruleset) {
	t.Helper()
	s, r := retryTestService(t)
	r.IntervalSeconds = 60
	r, err := s.Save(r, false)
	if err != nil {
		t.Fatal(err)
	}
	r, err = s.Build(context.Background(), r.ID)
	if err != nil {
		t.Fatal(err)
	}
	r.CustomRules = append(r.CustomRules, "new.test")
	r, err = s.Save(r, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.Build(context.Background(), r.ID); err != nil {
		t.Fatal(err)
	}
	r, err = s.Rollback(context.Background(), r.ID)
	if err != nil {
		t.Fatal(err)
	}
	return s, r
}

func TestRollbackHoldPersistsAndRejectsStaleScheduledBuild(t *testing.T) {
	s, r := heldRuleset(t)
	if !r.RollbackHold || !r.RollbackUntil.IsZero() {
		t.Fatalf("rollback flags: %+v", r)
	}
	if s.buildDue(r, time.Now().Add(365*24*time.Hour)) {
		t.Fatal("hold expired")
	}
	reopened, err := New(s.Config)
	if err != nil {
		t.Fatal(err)
	}
	r, _ = reopened.Store.Get(r.ID)
	if !r.RollbackHold || reopened.buildDue(r, time.Now().Add(time.Hour)) {
		t.Fatal("hold lost after restart")
	}
	before := r.LastBuild.Generation
	if _, err := reopened.build(context.Background(), r.ID, false); err != nil {
		t.Fatal(err)
	}
	r, _ = reopened.Store.Get(r.ID)
	if !r.RollbackHold || r.LastBuild.Generation != before {
		t.Fatal("stale scheduled work removed hold")
	}
	// A retry of the held generation's S3 objects remains eligible.
	reopened.S3 = &storage.S3{}
	r.LastBuild.S3Published = false
	r.LastError = "S3 не обновлён для: text"
	if !reopened.buildDue(r, time.Now().Add(time.Hour)) {
		t.Fatal("hold blocked S3 retry")
	}
}

func TestRollbackHoldReleaseActions(t *testing.T) {
	for _, action := range []string{"resume", "save", "manual-build", "import"} {
		t.Run(action, func(t *testing.T) {
			s, r := heldRuleset(t)
			before := r.LastBuild.Generation
			var err error
			switch action {
			case "resume":
				r, err = s.Resume(r.ID)
			case "save":
				r, err = s.Save(r, false)
			case "manual-build":
				r, err = s.Build(context.Background(), r.ID)
			case "import":
				st := s.ExportConfig()
				if st.Rulesets[0].RollbackHold {
					t.Fatal("export includes hold")
				}
				if err := s.ImportConfig(st); err != nil {
					t.Fatal(err)
				}
				unchanged, _ := s.Store.Get(r.ID)
				if !unchanged.RollbackHold {
					t.Fatal("no-op import removed hold")
				}
				st.Rulesets[0].Name = "Changed by import"
				err = s.ImportConfig(st)
				r, _ = s.Store.Get(r.ID)
			}
			if err != nil {
				t.Fatal(err)
			}
			if r.RollbackHold {
				t.Fatalf("%s kept hold", action)
			}
			if action != "manual-build" && r.LastBuild.Generation != before {
				t.Fatalf("%s unexpectedly built a generation", action)
			}
			if action == "resume" && !s.buildDue(r, time.Now()) {
				t.Fatal("resume did not allow scheduler")
			}
		})
	}
}

func TestResumeNoopBusyAndLegacyTimer(t *testing.T) {
	s, r := heldRuleset(t)
	s.busy[r.ID] = true
	if _, err := s.Resume(r.ID); err != ErrBusy {
		t.Fatalf("busy resume: %v", err)
	}
	delete(s.busy, r.ID)
	if _, err := s.Resume("missing"); err != ErrNotFound {
		t.Fatalf("missing resume: %v", err)
	}
	r, err := s.Resume(r.ID)
	if err != nil {
		t.Fatal(err)
	}
	until := time.Now().UTC().Add(time.Hour)
	if err := s.Store.Update(func(st *model.State) error { st.Rulesets[0].RollbackUntil = until; return nil }); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(s.Config.DataDir, "state.json")
	before, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	r, err = s.Resume(r.ID)
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) || !r.RollbackUntil.Equal(until) {
		t.Fatal("no-op resume modified legacy state")
	}
	if s.buildDue(r, until.Add(-time.Second)) || !s.buildDue(r, until.Add(time.Second)) {
		t.Fatal("legacy timer changed semantics")
	}
}

func TestManualBuildFailureStillReleasesHold(t *testing.T) {
	s, r := heldRuleset(t)
	if err := s.Store.Update(func(st *model.State) error {
		st.Rulesets[0].Sources = []model.Source{{Name: "Unavailable", URL: "http://127.0.0.1:1/rules", Format: "text", Behavior: "domain", Enabled: true}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Build(context.Background(), r.ID); err == nil {
		t.Fatal("unavailable source succeeded")
	}
	r, _ = s.Store.Get(r.ID)
	if r.RollbackHold {
		t.Fatal("accepted manual build kept hold after failure")
	}
}
