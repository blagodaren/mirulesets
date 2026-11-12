package service

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"time"

	"github.com/blagodaren/mirulesets/internal/model"
	"go.yaml.in/yaml/v3"
)

func configOnly(r model.Ruleset) model.Ruleset {
	r.Sources = append([]model.Source(nil), r.Sources...)
	r.LastBuild, r.LastError, r.UpdatedAt = nil, "", time.Time{}
	r.RollbackUntil = time.Time{}
	r.RollbackHold = false
	for i := range r.Sources {
		r.Sources[i].Status = nil
	}
	return r
}

// ExportConfig contains portable configuration, never credentials or paths to
// local generations. Revision protects existing sets during a round trip.
func (s *Service) ExportConfig() model.State {
	st := model.State{Version: 1, Rulesets: []model.Ruleset{}}
	for _, r := range s.Store.List() {
		st.Rulesets = append(st.Rulesets, RedactRuleset(configOnly(r)))
	}
	return st
}

// ImportConfig merges atomically, so omitted sets keep running. An exported
// snapshot cannot restore runtime paths, errors, or publication metadata.
func (s *Service) ImportConfig(in model.State) error { return s.importConfig(in, false) }

func (s *Service) importConfig(in model.State, declarative bool) error {
	if in.Version != 1 {
		return fmt.Errorf("неподдерживаемая версия конфигурации: %d", in.Version)
	}
	if len(in.Rulesets) > 1024 {
		return fmt.Errorf("максимум 1024 набора")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := []string{}
	err := s.Store.Update(func(st *model.State) error {
		seen := map[string]bool{}
		indexes := map[string]int{}
		for i, r := range st.Rulesets {
			indexes[r.ID] = i
		}
		for _, incoming := range in.Rulesets {
			r := configOnly(incoming)
			if seen[r.ID] {
				return fmt.Errorf("повторный ID в конфигурации: %s", r.ID)
			}
			seen[r.ID] = true
			if s.busy[r.ID] {
				return ErrBusy
			}
			i, exists := indexes[r.ID]
			if exists {
				old := st.Rulesets[i]
				if !declarative && r.Revision != old.Revision {
					return ErrConflict
				}
				preserveSourceHeaders(&r, old)
				if err := Validate(&r); err != nil {
					return fmt.Errorf("набор %s: %w", r.ID, err)
				}
				comparableOld := configOnly(old)
				comparableOld.Revision = 0
				comparableNew := configOnly(r)
				comparableNew.Revision = 0
				oldJSON, _ := json.Marshal(comparableOld)
				newJSON, _ := json.Marshal(comparableNew)
				if bytes.Equal(oldJSON, newJSON) {
					continue
				}
				if old.LastBuild != nil && old.LastBuild.Behavior == "" {
					old.LastBuild.Behavior = old.Behavior
				}
				r.LastBuild, r.Revision, r.UpdatedAt = old.LastBuild, old.Revision+1, time.Now().UTC()
				st.Rulesets[i] = r
			} else {
				if slices.Contains(st.PendingS3Deletes, r.ID) {
					return fmt.Errorf("S3 предыдущего набора с этим ID ещё очищается")
				}
				if err := Validate(&r); err != nil {
					return fmt.Errorf("набор %s: %w", r.ID, err)
				}
				r.Revision, r.UpdatedAt = 1, time.Now().UTC()
				st.Rulesets = append(st.Rulesets, r)
			}
			changed = append(changed, r.ID)
		}
		if len(st.Rulesets) > 1024 {
			return fmt.Errorf("максимум 1024 набора")
		}
		return validateDependencies(st.Rulesets)
	})
	if err == nil {
		for _, id := range changed {
			s.resetRetryLocked(id)
		}
	}
	return err
}

func (s *Service) Clone(id, newID, name string) (model.Ruleset, error) {
	r, ok := s.Store.Get(id)
	if !ok {
		return r, ErrNotFound
	}
	r = configOnly(r)
	r.ID, r.Name, r.Revision = newID, name, 0
	return s.Save(r, true)
}

func (s *Service) applyConfigFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("MI_RULESETS_FILE: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, (4<<20)+1))
	if err != nil {
		return err
	}
	if len(data) > 4<<20 {
		return fmt.Errorf("MI_RULESETS_FILE превышает 4 MiB")
	}
	var node yaml.Node
	dec := yaml.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&node); err != nil {
		return fmt.Errorf("MI_RULESETS_FILE: %w", err)
	}
	var rejectAliases func(*yaml.Node) error
	rejectAliases = func(n *yaml.Node) error {
		if n.Kind == yaml.AliasNode {
			return fmt.Errorf("YAML aliases не поддерживаются")
		}
		for _, child := range n.Content {
			if err := rejectAliases(child); err != nil {
				return err
			}
		}
		return nil
	}
	if err := rejectAliases(&node); err != nil {
		return err
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err != io.EOF {
		return fmt.Errorf("ожидается один YAML-документ")
	}
	var object map[string]any
	if err := node.Decode(&object); err != nil {
		return err
	}
	data, err = json.Marshal(object)
	if err != nil {
		return err
	}
	var st model.State
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&st); err != nil {
		return fmt.Errorf("MI_RULESETS_FILE: %w", err)
	}
	return s.importConfig(st, true)
}
