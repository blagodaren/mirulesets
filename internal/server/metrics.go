package server

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"strings"
)

// The monitoring credential is deliberately scoped to the metrics handler.
func (s *Server) protectMetrics(next http.Handler) http.Handler {
	fallback := s.protect(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization := r.Header.Get("Authorization")
		token := s.svc.Config.MetricsToken
		if token != "" && strings.HasPrefix(authorization, "Bearer ") &&
			subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(authorization, "Bearer ")), []byte(token)) == 1 {
			next.ServeHTTP(w, r)
			return
		}
		fallback.ServeHTTP(w, r)
	})
}

func metricLabel(value string) string {
	return strings.NewReplacer("\\", "\\\\", "\n", "\\n", "\"", "\\\"").Replace(value)
}

func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	var out strings.Builder
	metrics := s.svc.BuildMetrics()
	downloads := s.downloadCounts()
	out.WriteString("# HELP mirulesets_downloads_total Successful GET artifact downloads (200/206, excluding HEAD and 304) since process start.\n# TYPE mirulesets_downloads_total counter\n")
	for _, m := range metrics {
		fmt.Fprintf(&out, "mirulesets_downloads_total{ruleset=\"%s\"} %d\n", metricLabel(m.RulesetID), downloads[m.RulesetID])
	}
	out.WriteString("# HELP mirulesets_last_success_timestamp_seconds Unix time of the last successful local publication, or zero before the first build.\n# TYPE mirulesets_last_success_timestamp_seconds gauge\n")
	for _, m := range metrics {
		timestamp := float64(0)
		if !m.LastSuccessTime.IsZero() {
			timestamp = float64(m.LastSuccessTime.UnixNano()) / 1e9
		}
		fmt.Fprintf(&out, "mirulesets_last_success_timestamp_seconds{ruleset=\"%s\"} %.9f\n", metricLabel(m.RulesetID), timestamp)
	}
	out.WriteString("# HELP mirulesets_rules Number of rules in the last successful local publication.\n# TYPE mirulesets_rules gauge\n")
	for _, m := range metrics {
		fmt.Fprintf(&out, "mirulesets_rules{ruleset=\"%s\"} %d\n", metricLabel(m.RulesetID), m.RuleCount)
	}
	out.WriteString("# HELP mirulesets_build_errors_total Build failures including partial S3 failures since process start.\n# TYPE mirulesets_build_errors_total counter\n")
	for _, m := range metrics {
		fmt.Fprintf(&out, "mirulesets_build_errors_total{ruleset=\"%s\"} %d\n", metricLabel(m.RulesetID), m.ErrorsTotal)
	}
	out.WriteString("# HELP mirulesets_build_duration_seconds Duration of the most recent completed build attempt.\n# TYPE mirulesets_build_duration_seconds gauge\n")
	for _, m := range metrics {
		fmt.Fprintf(&out, "mirulesets_build_duration_seconds{ruleset=\"%s\"} %g\n", metricLabel(m.RulesetID), m.LastDurationSeconds)
	}
	_, _ = fmt.Fprint(w, out.String())
}
