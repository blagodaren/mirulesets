package server

import (
	"errors"
	"net/http"
	"slices"
	"strings"
	"unicode"

	"github.com/blagodaren/mirulesets/internal/model"
	"github.com/blagodaren/mirulesets/internal/service"
	"go.yaml.in/yaml/v3"
)

func redactRulesets(sets []model.Ruleset) []model.Ruleset {
	for i := range sets {
		sets[i] = service.RedactRuleset(sets[i])
	}
	return sets
}

func (s *Server) extendedAPI(w http.ResponseWriter, r *http.Request, path string) bool {
	switch path {
	case "config":
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Content-Disposition", `attachment; filename="state.json"`)
			respond(w, 200, s.svc.ExportConfig())
		case http.MethodPost:
			var state model.State
			if err := decode(w, r, &state); err != nil {
				fail(w, 400, err)
			} else if err := s.svc.ImportConfig(state); err != nil {
				s.serviceError(w, err)
			} else {
				respond(w, 200, map[string]any{"imported": len(state.Rulesets)})
			}
		default:
			return false
		}
		return true
	case "snippet":
		if r.Method == http.MethodGet {
			s.allSnippets(w, r)
			return true
		}
	case "lookup":
		if r.Method == http.MethodGet {
			matches, err := s.svc.Lookup(r.URL.Query().Get("query"))
			if err != nil {
				s.serviceError(w, err)
			} else {
				respond(w, 200, map[string]any{"matches": matches})
			}
			return true
		}
	}
	parts := strings.Split(path, "/")
	if r.Method != http.MethodPost || len(parts) != 3 || parts[0] != "rulesets" {
		return false
	}
	var result model.Ruleset
	var err error
	switch parts[2] {
	case "resume":
		result, err = s.svc.Resume(parts[1])
	case "rollback":
		result, err = s.svc.Rollback(r.Context(), parts[1])
	case "retry-s3":
		result, err = s.svc.RetryS3(r.Context(), parts[1])
	case "clone":
		var body struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		if err = decode(w, r, &body); err == nil {
			result, err = s.svc.Clone(parts[1], body.ID, body.Name)
		}
	default:
		return false
	}
	if err != nil {
		s.serviceError(w, err)
	} else {
		respond(w, 200, map[string]any{"ruleset": service.RedactRuleset(result)})
	}
	return true
}

func validPolicy(policy string) bool {
	return len(policy) <= 160 && !strings.ContainsRune(policy, ',') && !strings.ContainsFunc(policy, unicode.IsControl)
}

func (s *Server) allSnippets(w http.ResponseWriter, r *http.Request) {
	policy := strings.TrimSpace(r.URL.Query().Get("policy"))
	if !validPolicy(policy) {
		fail(w, 400, errors.New("название политики: до 160 байт, без запятых и управляющих символов"))
		return
	}
	base := s.svc.Config.PublicURL
	if base == "" {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		base = scheme + "://" + r.Host
	}
	providers := map[string]any{}
	routing := []string{}
	skipped := []string{}
	for _, set := range s.svc.Store.List() {
		format := ""
		if set.LastBuild != nil && set.LastBuild.Revision == set.Revision {
			for _, candidate := range []string{"mrs", "yaml", "text"} {
				if slices.ContainsFunc(set.LastBuild.Files, func(f model.Artifact) bool { return f.Format == candidate }) {
					format = candidate
					break
				}
			}
		}
		if format == "" {
			skipped = append(skipped, set.ID)
			continue
		}
		selected := policy
		if selected == "" {
			selected = set.Policy
		}
		if selected == "" {
			selected = "PROXY"
		}
		if !validPolicy(selected) {
			fail(w, 400, errors.New("недопустимая политика в наборе "+set.ID))
			return
		}
		providers[set.ID] = map[string]any{"type": "http", "behavior": set.Behavior, "format": format, "url": base + "/rules/" + set.ID + "." + service.Ext(format), "path": "./ruleset/" + set.ID + "." + service.Ext(format), "interval": set.IntervalSeconds}
		routing = append(routing, "RULE-SET,"+set.ID+","+selected)
	}
	b, err := yaml.Marshal(map[string]any{"rule-providers": providers, "rules": routing})
	if err != nil {
		fail(w, 500, errors.New("не удалось сформировать YAML"))
		return
	}
	respond(w, 200, map[string]any{"yaml": string(b), "included": len(providers), "skipped": skipped})
}

type downloadResponse struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (w *downloadResponse) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
		w.ResponseWriter.WriteHeader(status)
	}
}

func (w *downloadResponse) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += n
	return n, err
}

func (s *Server) downloadCounts() map[string]uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]uint64, len(s.downloads))
	for id, count := range s.downloads {
		out[id] = count
	}
	return out
}
