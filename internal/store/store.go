package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/blagodaren/mirulesets/internal/model"
)

type Store struct {
	mu    sync.RWMutex
	path  string
	state model.State
}

func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	s := &Store{path: filepath.Join(dir, "state.json"), state: model.State{Version: 1, Rulesets: []model.Ruleset{}}}
	b, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(b, &s.state); err != nil {
		return nil, fmt.Errorf("state.json повреждён: %w", err)
	}
	if s.state.Version != 1 {
		return nil, fmt.Errorf("неподдерживаемая версия state.json: %d", s.state.Version)
	}
	return s, nil
}

func clone(s model.State) model.State {
	b, _ := json.Marshal(s)
	var c model.State
	_ = json.Unmarshal(b, &c)
	return c
}
func (s *Store) List() []model.Ruleset {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return clone(s.state).Rulesets
}

func (s *Store) PendingS3Deletes() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]string(nil), s.state.PendingS3Deletes...)
}
func (s *Store) Get(id string) (model.Ruleset, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range s.state.Rulesets {
		if r.ID == id {
			copy := clone(model.State{Rulesets: []model.Ruleset{r}})
			return copy.Rulesets[0], true
		}
	}
	return model.Ruleset{}, false
}

// Publication keeps the public download path independent of editable rule lists.
func (s *Store) Publication(id string) (*model.Build, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range s.state.Rulesets {
		if r.ID == id && r.LastBuild != nil {
			b := *r.LastBuild
			b.Files = append([]model.Artifact(nil), r.LastBuild.Files...)
			return &b, true
		}
	}
	return nil, false
}

// Update serializes and durably writes before replacing the live snapshot.
func (s *Store) Update(fn func(*model.State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := clone(s.state)
	if err := fn(&next); err != nil {
		return err
	}
	b, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return err
	}
	if err = WriteAtomic(s.path, b, 0600); err != nil {
		return err
	}
	s.state = next
	return nil
}

func WriteAtomic(path string, b []byte, perm os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".write-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Chmod(perm); err == nil {
		_, err = f.Write(b)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (s *Store) S3DeleteTarget(id string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state.S3DeleteTargets[id]
}
