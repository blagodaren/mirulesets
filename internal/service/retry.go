package service

import (
	"strings"
	"time"

	"github.com/blagodaren/mirulesets/internal/model"
)

var retryDelays = [...]time.Duration{time.Minute, 5 * time.Minute, 15 * time.Minute, time.Hour}

// finishBuild runs only for attempts that acquired a worker slot and started.
// Queued cancellations and ErrBusy responses must not advance the backoff.
func (s *Service) finishBuild(id string, failed bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.busy, id)
	s.retryResultLocked(id, failed)
}

func (s *Service) retryResultLocked(id string, failed bool) {
	if _, exists := s.Store.Get(id); !exists || !failed {
		s.resetRetryLocked(id)
		return
	}
	if s.failures == nil {
		s.failures = make(map[string]int)
	}
	if s.nextTry == nil {
		s.nextTry = make(map[string]time.Time)
	}
	if s.failures[id] < len(retryDelays) {
		s.failures[id]++
	}
	s.nextTry[id] = time.Now().Add(retryDelays[s.failures[id]-1])
}

// resetRetryLocked is called after a successful save or delete, with mu held.
func (s *Service) resetRetryLocked(id string) {
	delete(s.failures, id)
	delete(s.nextTry, id)
}

func (s *Service) buildDue(r model.Ruleset, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buildDueLocked(r, now)
}

func (s *Service) buildDueLocked(r model.Ruleset, now time.Time) bool {
	if !r.Enabled || ((r.RollbackHold || now.Before(r.RollbackUntil)) && !s.s3RetryNeeded(r)) || s.busy[r.ID] || now.Before(s.nextTry[r.ID]) {
		return false
	}
	// A partially published S3 build has a fresh BuiltAt, but must still retry
	// when its backoff expires instead of waiting for the normal interval.
	return s.failures[r.ID] > 0 || r.LastError != "" || r.LastBuild == nil ||
		r.LastBuild.Revision != r.Revision ||
		now.Sub(r.LastBuild.BuiltAt) >= time.Duration(r.IntervalSeconds)*time.Second
}

func (s *Service) s3RetryNeeded(r model.Ruleset) bool {
	return s.S3 != nil && r.LastBuild != nil && !r.LastBuild.S3Published &&
		(strings.HasPrefix(r.LastError, "S3 не обновлён") || strings.HasPrefix(r.LastError, "Локальная сборка готова; S3"))
}
