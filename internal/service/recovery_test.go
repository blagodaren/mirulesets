package service

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestBuildRecoversUnavailablePreviousGeneration(t *testing.T) {
	for _, damage := range []string{"missing", "corrupt-canonical"} {
		t.Run(damage, func(t *testing.T) {
			s, r := retryTestService(t)
			r, err := s.Build(context.Background(), r.ID)
			if err != nil {
				t.Fatal(err)
			}
			previous := r.LastBuild.Generation
			if damage == "missing" {
				if err := s.removeArtifacts(r.ID, previous); err != nil {
					t.Fatal(err)
				}
			} else {
				path := filepath.Join(s.Config.DataDir, "artifacts", r.ID, previous, "canonical.json")
				if err := os.WriteFile(path, []byte(`["corrupted.test"]`), 0600); err != nil {
					t.Fatal(err)
				}
			}
			r, err = s.Build(context.Background(), r.ID)
			if err != nil {
				t.Fatal(err)
			}
			if r.LastBuild.Generation == previous || r.LastBuild.PreviousGeneration != "" || r.LastBuild.Added != 1 || r.LastBuild.Removed != 0 {
				t.Fatalf("recovery publication: %+v", r.LastBuild)
			}
			blobs, err := s.buildBlobs(r.ID, r.LastBuild)
			if err != nil || string(blobs["text"]) != "example.com\n" {
				t.Fatalf("recovered files: %q, %v", blobs, err)
			}
			warnings := 0
			for _, event := range s.Events() {
				if event.Level == "warning" && event.RulesetID == r.ID && event.Message == "Предыдущая сборка недоступна; сравнение пропущено" {
					warnings++
				}
			}
			if warnings != 1 {
				t.Fatalf("recovery warnings = %d", warnings)
			}
			if _, err := s.Rollback(context.Background(), r.ID); err == nil || err.Error() != "предыдущее поколение отсутствует" {
				t.Fatalf("rollback: %v", err)
			}
			current := r.LastBuild.Generation
			r, err = s.Build(context.Background(), r.ID)
			if err != nil || r.LastBuild.Generation != current {
				t.Fatalf("unchanged rebuild after recovery: %v", err)
			}
		})
	}
}
