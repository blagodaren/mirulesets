package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/blagodaren/mirulesets/internal/config"
	"github.com/blagodaren/mirulesets/internal/model"
	"github.com/blagodaren/mirulesets/internal/storage"
)

func publicationFixture(t *testing.T, c config.Config) (*Service, model.Ruleset) {
	t.Helper()
	if c.DataDir == "" {
		c.DataDir = t.TempDir()
	}
	s, err := New(c)
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.Save(model.Ruleset{ID: "publish", Name: "Publish", Behavior: "domain", CustomRules: []string{"example.com"}, IntervalSeconds: 3600, Formats: []string{"text", "yaml", "mrs"}, Enabled: true}, true)
	if err != nil {
		t.Fatal(err)
	}
	return s, r
}

func generationNames(t *testing.T, s *Service, id string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(s.Config.DataDir, "artifacts", id))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			names = append(names, e.Name())
		}
	}
	return names
}

func TestRetainsCurrentAndPreviousGenerationAndDeletesSet(t *testing.T) {
	s, r := publicationFixture(t, config.Config{})
	var previous string
	for n := range 4 {
		r.CustomRules = []string{fmt.Sprintf("build%d.example.com", n)}
		var err error
		r, err = s.Save(r, false)
		if err != nil {
			t.Fatal(err)
		}
		r, err = s.Build(context.Background(), r.ID)
		if err != nil {
			t.Fatal(err)
		}
		want := []string{r.LastBuild.Generation}
		if previous != "" {
			want = append(want, previous)
		}
		slices.Sort(want)
		if got := generationNames(t, s, r.ID); !reflect.DeepEqual(got, want) {
			t.Fatalf("generations = %v, want %v", got, want)
		}
		if r.LastBuild.PreviousGeneration != previous {
			t.Fatalf("previous = %q, want %q", r.LastBuild.PreviousGeneration, previous)
		}
		previous = r.LastBuild.Generation
	}
	if err := s.Delete(r.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(s.Config.DataDir, "artifacts", r.ID)); !os.IsNotExist(err) {
		t.Fatalf("deleted set left artifacts: %v", err)
	}
}

func TestUnchanged304PreservesGenerationAndFileModificationTime(t *testing.T) {
	var conditional atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"v1"` {
			conditional.Add(1)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		io.WriteString(w, "source.example.com\n")
	}))
	defer upstream.Close()
	s, r := publicationFixture(t, config.Config{AllowPrivateSources: true})
	r.Sources = []model.Source{{URL: upstream.URL, Enabled: true, Behavior: "domain", Format: "text"}}
	r, err := s.Save(r, false)
	if err != nil {
		t.Fatal(err)
	}
	r, err = s.Build(context.Background(), r.ID)
	if err != nil {
		t.Fatal(err)
	}
	first := r.LastBuild
	file := filepath.Join(s.Config.DataDir, "artifacts", r.ID, first.Generation, "rules.txt")
	before, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	r, err = s.Build(context.Background(), r.ID)
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	if conditional.Load() != 1 || r.LastBuild.Generation != first.Generation || !after.ModTime().Equal(before.ModTime()) || !r.LastBuild.BuiltAt.After(first.BuiltAt) {
		t.Fatalf("unchanged response republished files or did not refresh time: %+v", r.LastBuild)
	}
	// Changing only configuration still advances the build revision, avoiding
	// an endless scheduler loop while retaining identical artifact bytes.
	r.Name = "Renamed"
	slices.Reverse(r.Formats)
	r, err = s.Save(r, false)
	if err != nil {
		t.Fatal(err)
	}
	r, err = s.Build(context.Background(), r.ID)
	if err != nil || r.LastBuild.Generation != first.Generation || r.LastBuild.Revision != r.Revision {
		t.Fatalf("metadata/reordered formats: %+v, %v", r.LastBuild, err)
	}
	if got := generationNames(t, s, r.ID); len(got) != 1 {
		t.Fatalf("unchanged builds created generations: %v", got)
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	r, err = s.Build(context.Background(), r.ID)
	if err != nil || r.LastBuild.Generation == first.Generation {
		t.Fatalf("missing artifact was not repaired: %v", err)
	}
}

func TestStartupCleansLegacyGenerationsAndDeletedSets(t *testing.T) {
	s, r := publicationFixture(t, config.Config{})
	for _, name := range []string{"g1", "g2", "g3", "g4", "notes"} {
		if err := os.MkdirAll(filepath.Join(s.Config.DataDir, "artifacts", r.ID, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(s.Config.DataDir, "artifacts", "deleted-set", "g1"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := s.Store.Update(func(st *model.State) error {
		st.Rulesets[0].LastBuild = &model.Build{Generation: "g3"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(s.Config)
	if err != nil {
		t.Fatal(err)
	}
	if got := generationNames(t, reopened, r.ID); !reflect.DeepEqual(got, []string{"g2", "g3", "notes"}) {
		t.Fatalf("legacy cleanup: %v", got)
	}
	if _, err := os.Stat(filepath.Join(s.Config.DataDir, "artifacts", "deleted-set")); !os.IsNotExist(err) {
		t.Fatalf("orphan set was not cleaned: %v", err)
	}
}

func TestFailedCommitPreservesPublishedGenerationAndRemovesNewFiles(t *testing.T) {
	s, r := publicationFixture(t, config.Config{})
	r, err := s.Build(context.Background(), r.ID)
	if err != nil {
		t.Fatal(err)
	}
	first := r.LastBuild.Generation
	r.CustomRules = []string{"changed.example.com"}
	r, err = s.Save(r, false)
	if err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(s.Config.DataDir, "state.json")
	if err = os.Rename(statePath, statePath+".backup"); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(statePath, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Build(context.Background(), r.ID); err == nil {
		t.Fatal("failed state write was accepted")
	}
	if got := generationNames(t, s, r.ID); !reflect.DeepEqual(got, []string{first}) {
		t.Fatalf("failed generation left behind: %v", got)
	}
	if published, ok := s.Store.Publication(r.ID); !ok || published.Generation != first {
		t.Fatal("failed commit replaced last good publication")
	}
	if err = s.Delete(r.ID); err == nil {
		t.Fatal("failed deletion state write was accepted")
	}
	if got := generationNames(t, s, r.ID); !reflect.DeepEqual(got, []string{first}) {
		t.Fatalf("failed delete removed last good publication: %v", got)
	}
}

func TestS3UnchangedSkipsUploadsButFailedOrNewDestinationRetries(t *testing.T) {
	var uploads atomic.Int32
	var broken atomic.Bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("unexpected S3 request: %s", r.Method)
		}
		uploads.Add(1)
		io.Copy(io.Discard, r.Body)
		if broken.Load() {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusForbidden)
			io.WriteString(w, "<Error><Code>AccessDenied</Code><Message>denied</Message></Error>")
			return
		}
		w.Header().Set("ETag", `"test"`)
	}))
	defer upstream.Close()
	s, r := publicationFixture(t, config.Config{S3: storage.Config{Endpoint: upstream.URL, Region: "us-east-1", Bucket: "rulesets", AccessKey: "test", SecretKey: "test", Prefix: "rules", PathStyle: true}})
	r, err := s.Build(context.Background(), r.ID)
	if err != nil || !r.LastBuild.S3Published {
		t.Fatalf("initial publication: %v", err)
	}
	first := r.LastBuild.Generation
	initialUploads := uploads.Load()
	s, err = New(s.Config)
	if err != nil {
		t.Fatal(err)
	}
	r, err = s.Build(context.Background(), r.ID)
	if err != nil || uploads.Load() != initialUploads || r.LastBuild.Generation != first {
		t.Fatalf("unchanged publication after restart: uploads=%d, err=%v", uploads.Load(), err)
	}
	// A destination change must publish once even if all bytes are identical.
	c := s.Config
	c.S3.Prefix = "new-destination"
	s, err = New(c)
	if err != nil {
		t.Fatal(err)
	}
	broken.Store(true)
	r, err = s.Build(context.Background(), r.ID)
	if err != nil || r.LastError == "" || r.LastBuild.S3Published || r.LastBuild.Generation != first {
		t.Fatalf("partial S3 result: %+v, %v", r, err)
	}
	failedUploads := uploads.Load()
	if failedUploads <= initialUploads {
		t.Fatal("changed destination did not trigger upload")
	}
	// Saving clears LastError, but must not lose durable pending publication.
	r, err = s.Save(r, false)
	if err != nil {
		t.Fatal(err)
	}
	s, err = New(c)
	if err != nil {
		t.Fatal(err)
	}
	broken.Store(false)
	r, err = s.Build(context.Background(), r.ID)
	if err != nil || r.LastError != "" || !r.LastBuild.S3Published || uploads.Load() <= failedUploads || r.LastBuild.Generation != first {
		t.Fatalf("S3 retry: %+v, %v", r, err)
	}
	if got := generationNames(t, s, r.ID); len(got) != 1 {
		t.Fatalf("S3 retries created local generations: %v", got)
	}
	if len(s.failures) != 0 {
		t.Fatal("successful S3 retry did not reset backoff")
	}
}

func TestArtifactRemovalRejectsUnsafePaths(t *testing.T) {
	s, _ := publicationFixture(t, config.Config{})
	for _, path := range [][2]string{{"../outside", ""}, {"valid", "../outside"}, {"", "g1"}, {"valid", "notes"}} {
		if err := s.removeArtifacts(path[0], path[1]); err == nil {
			t.Fatalf("unsafe path accepted: %v", path)
		}
	}
	outside := t.TempDir()
	if err := os.MkdirAll(filepath.Join(s.Config.DataDir, "artifacts"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(s.Config.DataDir, "artifacts", "linked")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := s.removeArtifacts("linked", ""); err == nil {
		t.Fatal("symlink was accepted for recursive deletion")
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatal("outside directory was removed")
	}
}

func TestSameSizeCorruptionIsRepaired(t *testing.T) {
	s, r := publicationFixture(t, config.Config{})
	r, err := s.Build(context.Background(), r.ID)
	if err != nil {
		t.Fatal(err)
	}
	first := r.LastBuild.Generation
	path := filepath.Join(s.Config.DataDir, "artifacts", r.ID, first, "rules.txt")
	if err := os.WriteFile(path, []byte("changed.com\n"), 0600); err != nil {
		t.Fatal(err)
	}
	r, err = s.Build(context.Background(), r.ID)
	if err != nil || r.LastBuild.Generation == first {
		t.Fatalf("same-size corruption was reused: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(s.Config.DataDir, "artifacts", r.ID, r.LastBuild.Generation, "rules.txt"))
	if err != nil || string(b) != "example.com\n" {
		t.Fatalf("artifact not repaired: %q, %v", b, err)
	}
}

func TestLegacyGenerationRepairsFromRemainingFormat(t *testing.T) {
	s, r := publicationFixture(t, config.Config{})
	r, err := s.Build(context.Background(), r.ID)
	if err != nil {
		t.Fatal(err)
	}
	first := r.LastBuild.Generation
	dir := filepath.Join(s.Config.DataDir, "artifacts", r.ID, first)
	// Legacy generations have no canonical snapshot. An intact YAML/MRS
	// output still supplies the previous rules if the first text file is lost.
	if err := os.Remove(filepath.Join(dir, "canonical.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "rules.txt")); err != nil {
		t.Fatal(err)
	}
	r, err = s.Build(context.Background(), r.ID)
	if err != nil || r.LastBuild.Generation == first {
		t.Fatalf("legacy generation could not repair a missing format: %v", err)
	}
	if r.LastBuild.Added != 0 || r.LastBuild.Removed != 0 {
		t.Fatalf("repair changed rule diff: %+v", r.LastBuild)
	}
}

func TestCancellationDuringUploadPreservesLastGood(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var shouldCancel atomic.Bool
	var uploads atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uploads.Add(1)
		io.Copy(io.Discard, r.Body)
		if shouldCancel.Load() {
			cancel()
		}
		w.Header().Set("ETag", `"test"`)
	}))
	defer upstream.Close()
	s, r := publicationFixture(t, config.Config{S3: storage.Config{Endpoint: upstream.URL, Region: "us-east-1", Bucket: "rulesets", AccessKey: "test", SecretKey: "test", PathStyle: true}})
	r, err := s.Build(context.Background(), r.ID)
	if err != nil {
		t.Fatal(err)
	}
	first := r.LastBuild.Generation
	r.CustomRules = []string{"changed.example.com"}
	r, err = s.Save(r, false)
	if err != nil {
		t.Fatal(err)
	}
	shouldCancel.Store(true)
	if _, err := s.Build(ctx, r.ID); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled build accepted: %v", err)
	}
	if got := generationNames(t, s, r.ID); !reflect.DeepEqual(got, []string{first}) {
		t.Fatalf("cancelled build changed generations: %v", got)
	}
	if published, ok := s.Store.Publication(r.ID); !ok || published.Generation != first || published.S3Published {
		t.Fatal("cancelled build replaced last good publication")
	}
	// Even a return to the old local content must repair S3: some PUTs may
	// have finished before the cancellation reached the client.
	beforeRetry := uploads.Load()
	shouldCancel.Store(false)
	r.CustomRules = []string{"example.com"}
	r, err = s.Save(r, false)
	if err != nil {
		t.Fatal(err)
	}
	r, err = s.Build(context.Background(), r.ID)
	if err != nil || r.LastBuild.Generation != first || uploads.Load() <= beforeRetry || !r.LastBuild.S3Published {
		t.Fatalf("cancelled S3 upload was not repaired: %v", err)
	}
}

func TestPolicyValidation(t *testing.T) {
	for _, policy := range []string{"", "  PROXY  ", "Моя группа 🚀", "DIRECT"} {
		r := model.Ruleset{ID: "policy", Name: "Policy", Policy: policy, Behavior: "domain", IntervalSeconds: 60, Formats: []string{"text"}}
		if err := Validate(&r); err != nil {
			t.Fatalf("valid policy %q rejected: %v", policy, err)
		}
		if (policy == "" || policy == "  PROXY  ") && r.Policy != "PROXY" {
			t.Fatalf("default policy: %q", r.Policy)
		}
	}
	for _, policy := range []string{"PROXY,no-resolve", "group\nother", "a\x00b", strings.Repeat("я", 161)} {
		r := model.Ruleset{ID: "policy", Name: "Policy", Policy: policy, Behavior: "domain", IntervalSeconds: 60, Formats: []string{"text"}}
		if err := Validate(&r); err == nil {
			t.Fatalf("invalid policy %q accepted", policy)
		}
	}
}
