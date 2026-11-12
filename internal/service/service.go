package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/blagodaren/mirulesets/internal/config"
	"github.com/blagodaren/mirulesets/internal/fetcher"
	"github.com/blagodaren/mirulesets/internal/model"
	"github.com/blagodaren/mirulesets/internal/rules"
	"github.com/blagodaren/mirulesets/internal/storage"
	"github.com/blagodaren/mirulesets/internal/store"
)

var ErrNotFound = errors.New("набор не найден")
var ErrConflict = errors.New("набор изменён в другой вкладке; обновите страницу")
var ErrBusy = errors.New("сборка уже выполняется; дождитесь её окончания")
var slug = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

type Service struct {
	Config    config.Config
	Store     *store.Store
	S3        *storage.S3
	fetch     *fetcher.Fetcher
	cleanupMu sync.Mutex
	mu        sync.Mutex
	busy      map[string]bool
	journal   *eventJournal
	metrics   map[string]buildObservation
	failures  map[string]int
	nextTry   map[string]time.Time
	jobs      chan struct{}
}

func New(c config.Config) (*Service, error) {
	s, err := store.Open(c.DataDir)
	if err != nil {
		return nil, err
	}
	x := &Service{Config: c, Store: s, fetch: fetcher.New(c.AllowPrivateSources, c.SourceAllowedCIDRs...), busy: map[string]bool{}, nextTry: map[string]time.Time{}, jobs: make(chan struct{}, 2)}
	if c.S3.Bucket != "" {
		x.S3, err = storage.NewS3(c.S3)
		if err != nil {
			return nil, err
		}
	}
	for _, r := range s.List() {
		if err := Validate(&r); err != nil {
			return nil, fmt.Errorf("state.json, набор %q: %w", r.ID, err)
		}
		if r.LastBuild != nil && (!generationName.MatchString(r.LastBuild.Generation) || (r.LastBuild.PreviousGeneration != "" && !generationName.MatchString(r.LastBuild.PreviousGeneration))) {
			return nil, fmt.Errorf("state.json: недопустимая generation")
		}
	}
	if err := validateDependencies(s.List()); err != nil {
		return nil, err
	}
	if err := x.initEvents(); err != nil {
		return nil, err
	}
	if c.RulesetsFile != "" {
		if err := x.applyConfigFile(c.RulesetsFile); err != nil {
			return nil, err
		}
	}
	for _, r := range s.List() {
		if err := x.cleanupArtifacts(r); err != nil {
			x.Event("warning", "Не удалось очистить старые сборки: "+err.Error(), r.ID)
		}
	}
	if err := x.cleanupOrphanArtifacts(); err != nil {
		x.Event("warning", "Не удалось очистить файлы удалённых наборов: "+err.Error(), "")
	}
	if err := x.cleanupS3Deletes(context.Background()); err != nil {
		x.Event("warning", err.Error(), "")
	}
	return x, nil
}

func Validate(r *model.Ruleset) error {
	if !slug.MatchString(r.ID) {
		return fmt.Errorf("ID: 1–64 символа a-z, 0-9, _ или -, первый символ — буква или цифра")
	}
	r.Name = strings.TrimSpace(r.Name)
	if r.Name == "" || len(r.Name) > 160 {
		return fmt.Errorf("название обязательно, максимум 160 байт")
	}
	r.Policy = strings.TrimSpace(r.Policy)
	if r.Policy == "" {
		r.Policy = "PROXY"
	}
	if utf8.RuneCountInString(r.Policy) > 160 || strings.ContainsRune(r.Policy, ',') || strings.ContainsFunc(r.Policy, unicode.IsControl) {
		return fmt.Errorf("группа Mihomo: максимум 160 символов, без запятых и управляющих символов")
	}
	if !slices.Contains([]string{"domain", "ipcidr", "classical"}, r.Behavior) {
		return fmt.Errorf("behavior: domain, ipcidr или classical")
	}
	if r.IntervalSeconds < 60 || r.IntervalSeconds > 2592000 {
		return fmt.Errorf("интервал обновления: от 60 до 2592000 секунд")
	}
	if len(r.Sources) > 256 {
		return fmt.Errorf("максимум 256 источников в одном наборе")
	}
	if len(r.Formats) == 0 {
		return fmt.Errorf("выберите хотя бы один выходной формат")
	}
	seen := map[string]bool{}
	formats := []string{}
	for _, f := range r.Formats {
		if !slices.Contains([]string{"yaml", "text", "mrs", "singbox", "srs"}, f) {
			return fmt.Errorf("неизвестный формат: %s", f)
		}
		if f == "mrs" && r.Behavior == "classical" {
			return fmt.Errorf("Mihomo не поддерживает classical в MRS; выберите YAML или text")
		}
		if !seen[f] {
			formats = append(formats, f)
			seen[f] = true
		}
	}
	r.Formats = formats
	if r.MaxDropPercent != nil && (math.IsNaN(*r.MaxDropPercent) || math.IsInf(*r.MaxDropPercent, 0) || *r.MaxDropPercent < 0 || *r.MaxDropPercent > 100) {
		return fmt.Errorf("порог падения должен быть от 0 до 100 процентов")
	}
	if len(r.Tags) > 20 {
		return fmt.Errorf("максимум 20 тегов")
	}
	tags := []string{}
	for _, tag := range r.Tags {
		tag = strings.TrimSpace(tag)
		if tag == "" || len(tag) > 64 {
			return fmt.Errorf("тег: 1–64 байта")
		}
		if !slices.Contains(tags, tag) {
			tags = append(tags, tag)
		}
	}
	r.Tags = tags
	sourceIDs := map[string]bool{}
	for i := range r.Sources {
		if r.Sources[i].Name == "" {
			r.Sources[i].Name = fmt.Sprintf("Источник %d", i+1)
		}
		if err := ValidateSource(&r.Sources[i], r.Behavior); err != nil {
			return fmt.Errorf("источник %d: %w", i+1, err)
		}
		if sourceIDs[r.Sources[i].ID] {
			return fmt.Errorf("повторный ID источника")
		}
		sourceIDs[r.Sources[i].ID] = true
	}

	var err error
	r.CustomRules, err = rules.Normalize(r.CustomRules, r.Behavior)
	if err != nil {
		return fmt.Errorf("свои правила: %w", err)
	}
	r.ExcludeRules, err = rules.Normalize(r.ExcludeRules, r.Behavior)
	if err != nil {
		return fmt.Errorf("исключения: %w", err)
	}
	if r.Sources == nil {
		r.Sources = []model.Source{}
	}
	return nil
}

func (s *Service) Save(r model.Ruleset, create bool) (model.Ruleset, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.Store.Get(r.ID); ok && !create {
		preserveSourceHeaders(&r, old)
	}
	if err := Validate(&r); err != nil {
		return r, err
	}
	if s.busy[r.ID] {
		return r, ErrBusy
	}
	r.RollbackHold = false
	r.RollbackUntil = time.Time{}
	err := s.Store.Update(func(st *model.State) error {
		for i, old := range st.Rulesets {
			if old.ID == r.ID {
				if create || old.Revision != r.Revision {
					return ErrConflict
				}
				r.Revision = old.Revision + 1
				r.UpdatedAt = time.Now().UTC()
				if old.LastBuild != nil && old.LastBuild.Behavior == "" {
					old.LastBuild.Behavior = old.Behavior
				}
				r.LastBuild = old.LastBuild
				r.LastError = ""
				r.RollbackUntil = time.Time{}
				st.Rulesets[i] = r
				return validateDependencies(st.Rulesets)
			}
		}
		if !create {
			return ErrNotFound
		}
		if slices.Contains(st.PendingS3Deletes, r.ID) {
			return fmt.Errorf("S3 предыдущего набора с этим ID ещё очищается")
		}
		if len(st.Rulesets) >= 1024 {
			return fmt.Errorf("максимум 1024 набора")
		}
		r.Revision = 1
		r.UpdatedAt = time.Now().UTC()
		r.LastBuild = nil
		r.LastError = ""
		st.Rulesets = append(st.Rulesets, r)
		return validateDependencies(st.Rulesets)
	})
	if err == nil {
		s.resetRetryLocked(r.ID)
	}
	return r, err
}

func (s *Service) Delete(id string) error {
	s.mu.Lock()
	locked := true
	defer func() {
		if locked {
			s.mu.Unlock()
		}
	}()
	if s.busy[id] {
		return ErrBusy
	}
	err := s.Store.Update(func(st *model.State) error {
		for i, r := range st.Rulesets {
			if r.ID == id {
				st.Rulesets = append(st.Rulesets[:i], st.Rulesets[i+1:]...)
				if err := validateDependencies(st.Rulesets); err != nil {
					return err
				}
				if s.S3 != nil {
					st.PendingS3Deletes = append(st.PendingS3Deletes, id)
					if st.S3DeleteTargets == nil {
						st.S3DeleteTargets = map[string]string{}
					}
					target := s.s3Target()
					if r.LastBuild != nil && r.LastBuild.S3Target != "" {
						target = r.LastBuild.S3Target
					}
					st.S3DeleteTargets[id] = target
				}
				return nil
			}
		}
		return ErrNotFound
	})
	if err != nil {
		return err
	}
	s.resetRetryLocked(id)
	delete(s.metrics, id)
	if err := s.removeArtifacts(id, ""); err != nil {
		s.Event("warning", "Набор удалён, но не удалось удалить его файлы: "+err.Error(), id)
		return fmt.Errorf("набор удалён, но очистка файлов не завершена: %w", err)
	}
	s.mu.Unlock()
	locked = false
	if err := s.cleanupS3Deletes(context.Background()); err != nil {
		s.Event("warning", err.Error(), id)
		return err
	}
	return nil
}
func Ext(format string) string {
	if format == "singbox" {
		return "json"
	}
	if format == "text" {
		return "txt"
	}
	return format
}
func ContentType(format string) string {
	switch format {
	case "singbox":
		return "application/json; charset=utf-8"
	case "mrs", "srs":
		return "application/octet-stream"
	case "yaml":
		return "application/yaml; charset=utf-8"
	default:
		return "text/plain; charset=utf-8"
	}
}

func (s *Service) source(ctx context.Context, src model.Source) ([]string, error) {
	lines, _, err := s.sourceWithStatus(ctx, src)
	return lines, err
}

func (s *Service) Build(ctx context.Context, id string) (result model.Ruleset, err error) {
	return s.build(ctx, id, true)
}

func (s *Service) build(ctx context.Context, id string, manual bool) (result model.Ruleset, err error) {
	s.mu.Lock()
	if s.busy[id] {
		s.mu.Unlock()
		return result, ErrBusy
	}
	r, ok := s.Store.Get(id)
	if !ok {
		s.mu.Unlock()
		return r, ErrNotFound
	}
	if err := ctx.Err(); err != nil {
		s.mu.Unlock()
		return r, err
	}
	now := time.Now()
	// Recheck the live state under the lock: a queued scheduler snapshot may
	// predate a rollback or a completed publication.
	if !manual && (r.RollbackHold || now.Before(r.RollbackUntil) || !s.buildDueLocked(r, now)) {
		s.mu.Unlock()
		return r, nil
	}
	if manual && (r.RollbackHold || !r.RollbackUntil.IsZero()) {
		r.RollbackHold = false
		r.RollbackUntil = time.Time{}
		if err := s.commitPublication(r); err != nil {
			s.mu.Unlock()
			return r, err
		}
	}
	s.busy[id] = true
	s.mu.Unlock()
	startedAttempt := false
	defer func() {
		if startedAttempt {
			s.finishBuild(id, err != nil || result.LastError != "")
		} else {
			s.mu.Lock()
			delete(s.busy, id)
			s.mu.Unlock()
		}
	}()
	select {
	case s.jobs <- struct{}{}:
		defer func() { <-s.jobs }()
	case <-ctx.Done():
		return r, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return r, err
	}
	startedAttempt = true
	started := time.Now()
	defer func() { s.recordBuild(id, started, err != nil || result.LastError != "") }()
	s.Event("info", "Сборка начата", id)
	defer func() {
		if err != nil {
			_ = s.Store.Update(func(st *model.State) error {
				for i := range st.Rulesets {
					if st.Rulesets[i].ID == id && st.Rulesets[i].Revision == r.Revision {
						st.Rulesets[i].LastError = err.Error()
						st.Rulesets[i].Sources = r.Sources
					}
				}
				return nil
			})
			s.Event("error", err.Error(), id)
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	parts := make([][]string, len(r.Sources))
	errs := make([]error, len(r.Sources))
	var wg sync.WaitGroup
	var budgetMu sync.Mutex
	totalRules, totalBytes := len(r.CustomRules), 0
	for _, line := range r.CustomRules {
		totalBytes += len(line)
	}
	work := make(chan int)
	for n := 0; n < 4; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range work {
				if ctx.Err() != nil {
					errs[i] = ctx.Err()
					continue
				}
				src := r.Sources[i]
				lines, status, e := s.sourceWithStatus(ctx, src)
				if e == nil {
					lines, e = rules.Transform(lines, src.Behavior, r.Behavior)
				}
				if e == nil {
					bytes := 0
					for _, line := range lines {
						bytes += len(line)
					}
					budgetMu.Lock()
					totalRules += len(lines)
					totalBytes += bytes
					if totalRules > rules.MaxRules || totalBytes > rules.MaxInputBytes {
						e = fmt.Errorf("общий размер источников превышает 1 000 000 правил или 64 MiB")
						lines = nil
						cancel()
					}
					budgetMu.Unlock()
				}
				if e != nil && len(src.Headers) > 0 {
					e = fmt.Errorf("не удалось обработать авторизованный источник")
				}
				if e != nil {
					status.Error = e.Error()
				}
				r.Sources[i].Status = &status
				parts[i] = lines
				errs[i] = e
			}
		}()
	}
	sourceCount := 0
	for i, src := range r.Sources {
		if src.Enabled {
			sourceCount++
			work <- i
		}
	}
	close(work)
	wg.Wait()
	var lines []string
	for i, part := range parts {
		if errs[i] != nil {
			return r, fmt.Errorf("источник %d (%s): %w", i+1, r.Sources[i].Name, errs[i])
		}
		lines = append(lines, part...)
		if len(lines) > 2_000_000 {
			return r, fmt.Errorf("слишком много правил: максимум 2 000 000")
		}
	}
	lines = append(lines, r.CustomRules...)
	lines, err = rules.Normalize(lines, r.Behavior)
	if err != nil {
		return r, err
	}
	excluded := make(map[string]bool, len(r.ExcludeRules))
	for _, v := range r.ExcludeRules {
		excluded[v] = true
	}
	kept := lines[:0]
	for _, line := range lines {
		if !excluded[line] {
			kept = append(kept, line)
		}
	}
	lines = kept
	added, removed, previousAvailable, e := s.checkRuleChange(r, lines)
	if e != nil {
		return r, e
	}
	build := &model.Build{CanonicalSHA256: canonicalHash(lines), Behavior: r.Behavior, Added: added, Removed: removed, BuiltAt: time.Now().UTC(), RuleCount: len(lines), SourceCount: sourceCount, Revision: r.Revision, Files: []model.Artifact{}}
	blobs := make(map[string][]byte)
	for _, format := range r.Formats {
		b, e := rules.Encode(lines, format, r.Behavior)
		if e != nil {
			return r, e
		}
		sum := sha256.Sum256(b)
		build.Files = append(build.Files, model.Artifact{Format: format, URL: s.Config.PublicURL + "/rules/" + id + "." + Ext(format), Size: len(b), SHA256: hex.EncodeToString(sum[:])})
		blobs[format] = b
	}
	if err = ctx.Err(); err != nil {
		return r, err
	}
	unchanged := previousAvailable && s.sameArtifacts(id, r.LastBuild, build) && r.LastBuild.Behavior == build.Behavior && r.LastBuild.CanonicalSHA256 == build.CanonicalSHA256
	committed := false
	if unchanged {
		build.CanonicalSHA256 = r.LastBuild.CanonicalSHA256
		build.Generation = r.LastBuild.Generation
		build.PreviousGeneration = r.LastBuild.PreviousGeneration
	} else {
		build.Generation = fmt.Sprintf("g%d", started.UnixNano())
		if previousAvailable {
			build.PreviousGeneration = r.LastBuild.Generation
		}
		dir, e := s.artifactPath(id, build.Generation)
		if e != nil {
			return r, e
		}
		if e = os.MkdirAll(filepath.Dir(dir), 0700); e != nil {
			return r, e
		}
		if e = os.Mkdir(dir, 0700); e != nil {
			return r, e
		}
		defer func() {
			if !committed {
				if e := s.removeArtifacts(id, build.Generation); e != nil {
					s.Event("warning", "Не удалось удалить незавершённую сборку: "+e.Error(), id)
				}
			}
		}()
		if e = s.writeGenerationRules(dir, lines, build); e != nil {
			return r, e
		}
		for _, f := range build.Files {
			if e = store.WriteAtomic(filepath.Join(dir, "rules."+Ext(f.Format)), blobs[f.Format], 0600); e != nil {
				return r, e
			}
		}
	}
	// Local publication remains atomic; S3 objects are independently retryable.
	s3Errors, e := s.uploadBuild(ctx, id, build, blobs, r.LastBuild, true)
	if e != nil {
		return r, e
	}
	if err = ctx.Err(); err != nil {
		return r, err
	}

	build.DurationMS = time.Since(started).Milliseconds()
	if !unchanged {
		if previousAvailable {
			if e := s.ensureBuildMetadata(id, r.LastBuild); e != nil {
				return r, e
			}
		}
		if e := s.ensureBuildMetadata(id, build); e != nil {
			return r, e
		}
	}
	r.LastBuild = build
	r.RollbackUntil = time.Time{}
	r.LastError = ""
	if len(s3Errors) > 0 {
		r.LastError = "Локальная сборка готова; S3 не обновлён для: " + strings.Join(s3Errors, ", ") + ". Проверьте доступ к bucket и повторите отправку S3."
	}
	err = s.Store.Update(func(st *model.State) error {
		for i, old := range st.Rulesets {
			if old.ID == id {
				if old.Revision != r.Revision {
					return ErrConflict
				}
				st.Rulesets[i] = r
				return nil
			}
		}
		return ErrNotFound
	})
	if err != nil {
		return r, err
	}
	// Cleanup may remove older generations only after this one is durable.
	committed = true
	if e := s.cleanupArtifacts(r); e != nil {
		s.Event("warning", "Не удалось очистить старые сборки: "+e.Error(), id)
	}
	if unchanged {
		s.Event("success", fmt.Sprintf("Проверено правил: %d · файлы не изменились", len(lines)), id)
	} else {
		s.Event("success", fmt.Sprintf("Опубликовано правил: %d · к предыдущей сборке +%d / −%d · %d мс", len(lines), build.Added, build.Removed, build.DurationMS), id)
	}
	if r.LastError != "" {
		s.Event("error", r.LastError, id)
	}
	return r, nil
}

func (s *Service) RunScheduler(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	var workers sync.WaitGroup
	defer workers.Wait()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			// Retry durable deletion tombstones without touching live sets.
			if err := s.cleanupS3Deletes(ctx); err != nil {
				s.Event("warning", err.Error(), "")
			}
			for _, r := range s.Store.List() {
				if s.buildDue(r, now) {
					workers.Add(1)
					go func(set model.Ruleset) {
						defer workers.Done()
						if s.s3RetryNeeded(set) {
							_, _ = s.RetryS3(ctx, set.ID)
						} else {
							_, _ = s.build(ctx, set.ID, false)
						}
					}(r)
				}
			}
		}
	}
}
