package service

import (
	"context"
	"testing"
	"time"

	"github.com/blagodaren/mirulesets/internal/config"
	"github.com/blagodaren/mirulesets/internal/model"
)

func retryTestService(t *testing.T) (*Service, model.Ruleset) {
	t.Helper()
	s, err := New(config.Config{DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.Save(model.Ruleset{
		ID: "retry-test", Name: "Retry test", Behavior: "domain",
		Formats: []string{"text"}, CustomRules: []string{"example.com"},
		IntervalSeconds: 86400, Enabled: true,
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	return s, r
}

func TestRetryBackoffEscalatesAndResets(t *testing.T) {
	s, r := retryTestService(t)
	for i, delay := range []time.Duration{time.Minute, 5 * time.Minute, 15 * time.Minute, time.Hour, time.Hour} {
		s.busy[r.ID] = true
		before := time.Now()
		s.finishBuild(r.ID, true)
		after := time.Now()
		if retry := s.nextTry[r.ID]; retry.Before(before.Add(delay)) || retry.After(after.Add(delay)) {
			t.Fatalf("attempt %d: retry %s, wanted delay %s", i+1, retry, delay)
		}
		if s.busy[r.ID] {
			t.Fatal("finished build remains busy")
		}
	}
	s.finishBuild(r.ID, false)
	if _, exists := s.failures[r.ID]; exists {
		t.Fatal("success did not clear failure count")
	}
	if _, exists := s.nextTry[r.ID]; exists {
		t.Fatal("success did not clear retry deadline")
	}
	s.finishBuild(r.ID, true)
	if s.failures[r.ID] != 1 || time.Until(s.nextTry[r.ID]) > time.Minute {
		t.Fatal("failure after success did not restart at one minute")
	}
	s.finishBuild("unknown-id", true)
	if _, exists := s.nextTry["unknown-id"]; exists {
		t.Fatal("unknown ruleset acquired retry state")
	}
}

func TestSchedulerRetriesPartialFailureAfterBackoff(t *testing.T) {
	s, r := retryTestService(t)
	now := time.Now()
	r.LastBuild = &model.Build{BuiltAt: now, Revision: r.Revision}
	r.LastError = "S3 unavailable"
	s.finishBuild(r.ID, true)
	retry := s.nextTry[r.ID]
	if s.buildDue(r, retry.Add(-time.Nanosecond)) {
		t.Fatal("retry scheduled before backoff elapsed")
	}
	if !s.buildDue(r, retry) {
		t.Fatal("partial failure incorrectly waited for normal daily interval")
	}
	r.Enabled = false
	if s.buildDue(r, retry) {
		t.Fatal("disabled ruleset retried")
	}
	r.Enabled = true
	s.busy[r.ID] = true
	if s.buildDue(r, retry) {
		t.Fatal("busy ruleset retried")
	}
	s.finishBuild(r.ID, false)
	r.LastError = ""
	if s.buildDue(r, now.Add(time.Hour)) {
		t.Fatal("successful build ignored normal daily interval")
	}
	if !s.buildDue(r, now.Add(24*time.Hour)) {
		t.Fatal("normal daily interval did not become due")
	}
	// LastError survives restart even though the in-memory counter does not.
	r.LastError = "S3 unavailable"
	if !s.buildDue(r, now.Add(time.Second)) {
		t.Fatal("persisted partial failure was not retried after restart")
	}
}

func TestSaveAndDeleteClearRetryState(t *testing.T) {
	s, r := retryTestService(t)
	s.finishBuild(r.ID, true)
	var err error
	r, err = s.Save(r, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := s.nextTry[r.ID]; exists || s.failures[r.ID] != 0 {
		t.Fatal("saving configuration did not clear retry state")
	}
	s.finishBuild(r.ID, true)
	if err := s.Delete(r.ID); err != nil {
		t.Fatal(err)
	}
	if _, exists := s.nextTry[r.ID]; exists || s.failures[r.ID] != 0 {
		t.Fatal("deleting ruleset did not clear retry state")
	}
}

func TestBuildRejectedBeforeStartPreservesRetryState(t *testing.T) {
	s, r := retryTestService(t)
	s.finishBuild(r.ID, true)
	retry := s.nextTry[r.ID]
	s.busy[r.ID] = true
	if _, err := s.Build(context.Background(), r.ID); err != ErrBusy {
		t.Fatalf("busy build error = %v", err)
	}
	delete(s.busy, r.ID)
	if s.failures[r.ID] != 1 || !s.nextTry[r.ID].Equal(retry) {
		t.Fatal("busy response changed backoff")
	}
	for n := 0; n < cap(s.jobs); n++ {
		s.jobs <- struct{}{}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Build(ctx, r.ID); err != context.Canceled {
		t.Fatalf("queued cancelled build error = %v", err)
	}
	if s.busy[r.ID] || s.failures[r.ID] != 1 || !s.nextTry[r.ID].Equal(retry) {
		t.Fatal("queued cancellation changed backoff or left ruleset busy")
	}
	if _, err := s.Build(context.Background(), "unknown-id"); err != ErrNotFound {
		t.Fatalf("unknown build error = %v", err)
	}
	if _, exists := s.nextTry["unknown-id"]; exists {
		t.Fatal("unknown build acquired retry state")
	}
}
