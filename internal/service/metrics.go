package service

import "time"

// BuildMetric is one ruleset's monitoring snapshot. Error counters reset when
// the process restarts or the ruleset is deleted.
type BuildMetric struct {
	RulesetID           string
	LastSuccessTime     time.Time
	RuleCount           int
	ErrorsTotal         uint64
	LastDurationSeconds float64
}

type buildObservation struct {
	errors   uint64
	duration time.Duration
}

// recordBuild observes only attempts that acquired a build slot. A failed S3
// publication counts as an error even when local artifacts remain available.
func (s *Service) recordBuild(id string, started time.Time, failed bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.metrics == nil {
		s.metrics = make(map[string]buildObservation)
	}
	m := s.metrics[id]
	m.duration = time.Since(started)
	if failed {
		m.errors++
	}
	s.metrics[id] = m
}

func (s *Service) BuildMetrics() []BuildMetric {
	sets := s.Store.List()
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]BuildMetric, 0, len(sets))
	for _, r := range sets {
		m := BuildMetric{RulesetID: r.ID}
		if r.LastBuild != nil {
			m.LastSuccessTime = r.LastBuild.BuiltAt
			m.RuleCount = r.LastBuild.RuleCount
			m.LastDurationSeconds = float64(r.LastBuild.DurationMS) / 1000
		}
		if observed, ok := s.metrics[r.ID]; ok {
			m.ErrorsTotal = observed.errors
			m.LastDurationSeconds = observed.duration.Seconds()
		}
		result = append(result, m)
	}
	return result
}
