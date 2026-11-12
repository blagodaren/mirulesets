package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/blagodaren/mirulesets/internal/model"
	"github.com/blagodaren/mirulesets/internal/rules"
	"github.com/blagodaren/mirulesets/internal/store"
)

func readRegular(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, fmt.Errorf("недопустимый файл сборки")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err == nil && int64(len(b)) > limit {
		err = fmt.Errorf("файл сборки превышает лимит")
	}
	return b, err
}

func (s *Service) generationRules(id string, b *model.Build) ([]string, error) {
	if b == nil {
		return nil, fmt.Errorf("у набора ещё нет опубликованной сборки")
	}
	dir, err := s.artifactPath(id, b.Generation)
	if err != nil {
		return nil, err
	}
	data, err := readRegular(filepath.Join(dir, "canonical.json"), rules.MaxInputBytes*6)
	if err == nil && b.CanonicalSHA256 != "" {
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != b.CanonicalSHA256 {
			return nil, fmt.Errorf("контрольная сумма канонических правил не совпадает")
		}
		var lines []string
		if err = json.Unmarshal(data, &lines); err != nil {
			return nil, err
		}
		if len(lines) != b.RuleCount {
			return nil, fmt.Errorf("число правил поколения не совпадает с метаданными")
		}
		behavior := b.Behavior
		if behavior == "" {
			if r, ok := s.Store.Get(id); ok {
				behavior = r.Behavior
			}
		}
		return rules.Normalize(lines, behavior)
	}
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	behavior := b.Behavior
	if behavior == "" {
		if r, ok := s.Store.Get(id); ok {
			behavior = r.Behavior
		}
	}
	var lastErr error
	for _, f := range b.Files {
		if f.Format != "yaml" && f.Format != "text" && f.Format != "mrs" && f.Format != "singbox" {
			continue
		}
		data, e := readRegular(filepath.Join(dir, "rules."+Ext(f.Format)), rules.MaxInputBytes*6)
		if e != nil {
			lastErr = e
			continue
		}
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != f.SHA256 {
			lastErr = fmt.Errorf("контрольная сумма предыдущей сборки не совпадает")
			continue
		}
		lines, e := rules.Parse(data, f.Format, behavior)
		if e == nil {
			return lines, nil
		}
		lastErr = e
	}
	if lastErr != nil {
		return nil, lastErr
	}

	return nil, fmt.Errorf("правила предыдущего поколения недоступны")
}

func (s *Service) writeGenerationRules(dir string, lines []string, build *model.Build) error {
	data, err := json.Marshal(lines)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	build.CanonicalSHA256 = hex.EncodeToString(sum[:])
	return store.WriteAtomic(filepath.Join(dir, "canonical.json"), data, 0600)
}

func (s *Service) ensureBuildMetadata(id string, build *model.Build) error {
	dir, err := s.artifactPath(id, build.Generation)
	if err != nil {
		return err
	}
	path := filepath.Join(dir, "build.json")
	if _, err := os.Lstat(path); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	data, err := json.Marshal(build)
	if err != nil {
		return err
	}
	return store.WriteAtomic(path, data, 0600)
}

func ruleDiff(old, next []string) (added, removed int) {
	prior := make(map[string]bool, len(old))
	current := make(map[string]bool, len(next))
	for _, line := range old {
		prior[line] = true
	}
	for _, line := range next {
		current[line] = true
		if !prior[line] {
			added++
		}
	}
	for _, line := range old {
		if !current[line] {
			removed++
		}
	}
	return
}

func (s *Service) checkRuleChange(r model.Ruleset, lines []string) (added, removed int, previousAvailable bool, err error) {
	if r.LastBuild == nil {
		return len(lines), 0, false, nil
	}
	threshold := 50.0
	if r.MaxDropPercent != nil {
		threshold = *r.MaxDropPercent
	}
	previous := r.LastBuild.RuleCount
	if r.LastBuild.Revision == r.Revision && previous > 0 && float64(previous-len(lines))*100 > threshold*float64(previous) {
		return 0, 0, false, fmt.Errorf("публикация заблокирована: число правил упало с %d до %d (%.2f%%), порог %.2f%%; предыдущая сборка сохранена", previous, len(lines), 100*float64(previous-len(lines))/float64(previous), threshold)
	}
	old, err := s.generationRules(r.ID, r.LastBuild)
	if err != nil {
		s.Event("warning", "Предыдущая сборка недоступна; сравнение пропущено", r.ID)
		return len(lines), 0, false, nil
	}
	added, removed = ruleDiff(old, lines)
	return added, removed, true, nil
}

func (s *Service) uploadBuild(ctx context.Context, id string, b *model.Build, blobs map[string][]byte, old *model.Build, reuse bool) ([]string, error) {
	failed := []string{}
	if s.S3 == nil {
		return failed, nil
	}
	b.S3Target = s.s3Target()
	sends := map[string]bool{}
	for _, f := range b.Files {
		skip := false
		if reuse && old != nil && old.S3Target == b.S3Target {
			for _, prior := range old.Files {
				if prior.Format == f.Format && prior.SHA256 == f.SHA256 && (prior.S3Published || old.S3Published) {
					skip = true
				}
			}
		}
		if !skip {
			sends[f.Format] = true
		}
	}
	// Stable S3 keys may change before the local pointer can commit. Persist this
	// uncertainty first so a crash/cancellation cannot make a later build skip PUT.
	if len(sends) > 0 {
		if err := s.Store.Update(func(st *model.State) error {
			for i := range st.Rulesets {
				if st.Rulesets[i].ID == id {
					current := st.Rulesets[i].LastBuild
					if current != nil {
						current.S3Published = false
						for j := range current.Files {
							if sends[current.Files[j].Format] {
								current.Files[j].S3Published = false
							}
						}
						st.Rulesets[i].LastError = "S3 не обновлён: отправка не завершена"
					}
					return nil
				}
			}
			return ErrNotFound
		}); err != nil {
			return nil, err
		}
	}
	for i := range b.Files {
		f := &b.Files[i]
		if reuse && old != nil && old.S3Target == b.S3Target {
			found := false
			for _, prior := range old.Files {
				if prior.Format == f.Format && prior.SHA256 == f.SHA256 && (prior.S3Published || old.S3Published) {
					f.S3Published, f.S3URL, f.S3Error = true, prior.S3URL, ""
					found = true
					break
				}
			}
			if found {
				continue
			}
		}
		public, err := s.S3.Put(ctx, id+"."+Ext(f.Format), ContentType(f.Format), blobs[f.Format])
		f.S3Published, f.S3URL, f.S3Error = err == nil, public, ""
		if err != nil {
			f.S3Error = "Не удалось отправить объект в S3"
			failed = append(failed, f.Format)
		}
	}
	b.S3Published = len(failed) == 0
	return failed, nil
}

func (s *Service) publicationOperation(id string) (model.Ruleset, func(), error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.busy[id] {
		return model.Ruleset{}, nil, ErrBusy
	}
	r, ok := s.Store.Get(id)
	if !ok {
		return r, nil, ErrNotFound
	}
	if r.LastBuild == nil {
		return r, nil, fmt.Errorf("у набора ещё нет сборки")
	}
	s.busy[id] = true
	return r, func() { s.mu.Lock(); delete(s.busy, id); s.mu.Unlock() }, nil
}

func (s *Service) buildBlobs(id string, b *model.Build) (map[string][]byte, error) {
	dir, err := s.artifactPath(id, b.Generation)
	if err != nil {
		return nil, err
	}
	blobs := map[string][]byte{}
	for _, f := range b.Files {
		switch f.Format {
		case "text", "yaml", "mrs", "singbox", "srs":
		default:
			return nil, fmt.Errorf("неизвестный формат поколения")
		}
		data, err := readRegular(filepath.Join(dir, "rules."+Ext(f.Format)), rules.MaxInputBytes*6)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(data)
		if len(data) != f.Size || hex.EncodeToString(sum[:]) != f.SHA256 {
			return nil, fmt.Errorf("файл %s повреждён", f.Format)
		}
		blobs[f.Format] = data
	}
	return blobs, nil
}

func (s *Service) commitPublication(r model.Ruleset) error {
	return s.Store.Update(func(st *model.State) error {
		for i, old := range st.Rulesets {
			if old.ID == r.ID {
				if old.Revision != r.Revision {
					return ErrConflict
				}
				st.Rulesets[i] = r
				return nil
			}
		}
		return ErrNotFound
	})
}

func (s *Service) RetryS3(ctx context.Context, id string) (result model.Ruleset, err error) {
	r, release, err := s.publicationOperation(id)
	if err != nil {
		return r, err
	}
	defer release()
	if s.S3 == nil {
		return r, fmt.Errorf("S3 не настроен")
	}
	defer func() {
		s.mu.Lock()
		s.retryResultLocked(id, err != nil || result.LastError != "")
		s.mu.Unlock()
	}()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	blobs, err := s.buildBlobs(id, r.LastBuild)
	if err != nil {
		return r, err
	}
	old := *r.LastBuild
	old.Files = append([]model.Artifact(nil), r.LastBuild.Files...)
	failed, err := s.uploadBuild(ctx, id, r.LastBuild, blobs, &old, true)
	if err != nil {
		return r, err
	}
	if err = ctx.Err(); err != nil {
		return r, err
	}
	// Do not erase an unrelated failed-build diagnostic on a successful S3 retry.
	if strings.HasPrefix(r.LastError, "Локальная сборка готова; S3") || strings.HasPrefix(r.LastError, "S3 не обновлён") {
		r.LastError = ""
	}
	if len(failed) > 0 {
		r.LastError = "S3 не обновлён для: " + strings.Join(failed, ", ")
	}
	if err = s.commitPublication(r); err != nil {
		return r, err
	}
	if len(failed) > 0 {
		s.Event("error", r.LastError, id)
	} else {
		s.Event("success", "Отправка S3 завершена без пересборки", id)
	}
	return r, nil
}

func (s *Service) Rollback(ctx context.Context, id string) (model.Ruleset, error) {
	r, release, err := s.publicationOperation(id)
	if err != nil {
		return r, err
	}
	defer release()
	current := r.LastBuild
	if current.PreviousGeneration == "" {
		return r, fmt.Errorf("предыдущее поколение отсутствует")
	}
	dir, err := s.artifactPath(id, current.PreviousGeneration)
	if err != nil {
		return r, err
	}
	data, err := readRegular(filepath.Join(dir, "build.json"), 1<<20)
	if err != nil {
		return r, fmt.Errorf("метаданные предыдущего поколения недоступны: %w", err)
	}
	var previous model.Build
	if err = json.Unmarshal(data, &previous); err != nil {
		return r, err
	}
	if previous.Generation != current.PreviousGeneration || len(previous.Files) == 0 {
		return r, fmt.Errorf("некорректные метаданные предыдущего поколения")
	}
	blobs, err := s.buildBlobs(id, &previous)
	if err != nil {
		return r, err
	}
	before, err := s.generationRules(id, current)
	if err != nil {
		return r, err
	}
	after, err := s.generationRules(id, &previous)
	if err != nil {
		return r, err
	}
	if err = ctx.Err(); err != nil {
		return r, err
	}
	previous.PreviousGeneration = current.Generation
	previous.Added, previous.Removed = ruleDiff(before, after)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	failed, err := s.uploadBuild(ctx, id, &previous, blobs, nil, false)
	if err != nil {
		return r, err
	}
	if err = ctx.Err(); err != nil {
		return r, err
	}
	r.LastBuild, r.LastError = &previous, ""
	r.RollbackHold = true
	r.RollbackUntil = time.Time{}
	if len(failed) > 0 {
		r.LastError = "S3 не обновлён для: " + strings.Join(failed, ", ")
	}
	if err = s.commitPublication(r); err != nil {
		return r, err
	}
	s.mu.Lock()
	s.retryResultLocked(id, len(failed) > 0)
	s.mu.Unlock()
	if len(failed) > 0 {
		s.Event("error", r.LastError, id)
	}
	s.Event("success", fmt.Sprintf("Откат к %s: +%d / −%d правил", previous.Generation, previous.Added, previous.Removed), id)
	return r, nil
}

func canonicalHash(lines []string) string {
	data, _ := json.Marshal(lines)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func (s *Service) Resume(id string) (model.Ruleset, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.busy[id] {
		return model.Ruleset{}, ErrBusy
	}
	r, ok := s.Store.Get(id)
	if !ok {
		return r, ErrNotFound
	}
	if !r.RollbackHold {
		return r, nil
	}
	r.RollbackHold = false
	if err := s.commitPublication(r); err != nil {
		return r, err
	}
	return r, nil
}
