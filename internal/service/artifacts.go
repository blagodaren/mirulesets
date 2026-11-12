package service

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/blagodaren/mirulesets/internal/model"
)

var generationName = regexp.MustCompile(`^g[0-9]+$`)

// artifactPath resolves the configured root and rejects links below it before
// any recursive removal. Only service-owned IDs and generations are accepted.
func (s *Service) artifactPath(id, generation string) (string, error) {
	if !slug.MatchString(id) || (generation != "" && !generationName.MatchString(generation)) {
		return "", fmt.Errorf("недопустимый путь артефакта")
	}
	root, err := filepath.Abs(s.Config.DataDir)
	if err != nil {
		return "", err
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	parts := []string{"artifacts", id}
	if generation != "" {
		parts = append(parts, generation)
	}
	target := root
	for _, part := range parts {
		target = filepath.Join(target, part)
		info, err := os.Lstat(target)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return "", err
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("путь артефакта должен быть каталогом без ссылок: %s", target)
		}
	}
	rel, err := filepath.Rel(filepath.Join(root, "artifacts"), target)
	if err != nil || rel == "." || rel == ".." || filepath.IsAbs(rel) || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("путь артефакта выходит за пределы artifacts")
	}
	return target, nil
}

func (s *Service) removeArtifacts(id, generation string) error {
	dir, err := s.artifactPath(id, generation)
	if err != nil {
		return err
	}
	return os.RemoveAll(dir)
}

// A delete commits state first so a failed state write cannot remove a live
// publication. Retry leftover filesystem cleanup at startup after a crash or
// transient filesystem error during deletion.
func (s *Service) cleanupOrphanArtifacts() error {
	root, err := filepath.Abs(s.Config.DataDir)
	if err != nil {
		return err
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return err
	}
	dir := filepath.Join(root, "artifacts")
	info, err := os.Lstat(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("artifacts должен быть каталогом без ссылок")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var cleanupErrors []error
	for _, e := range entries {
		if !e.IsDir() || !slug.MatchString(e.Name()) {
			continue
		}
		if _, exists := s.Store.Get(e.Name()); exists {
			continue
		}
		if err := s.removeArtifacts(e.Name(), ""); err != nil {
			cleanupErrors = append(cleanupErrors, err)
		}
	}
	return errors.Join(cleanupErrors...)
}

// cleanupArtifacts retains the published generation and its last predecessor.
// For pre-retention state files, find the nearest older generation once by name.
// Unrecognized entries are left alone, not treated as generated artifacts.
func (s *Service) cleanupArtifacts(r model.Ruleset) error {
	dir, err := s.artifactPath(r.ID, "")
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	current, previous := "", ""
	if r.LastBuild != nil {
		current, previous = r.LastBuild.Generation, r.LastBuild.PreviousGeneration
		if previous == "" {
			currentID, _ := strconv.ParseUint(strings.TrimPrefix(current, "g"), 10, 64)
			var previousID uint64
			for _, e := range entries {
				if !e.IsDir() || !generationName.MatchString(e.Name()) {
					continue
				}
				n, err := strconv.ParseUint(e.Name()[1:], 10, 64)
				if err == nil && n < currentID && n > previousID {
					previous, previousID = e.Name(), n
				}
			}
		}
	}
	var cleanupErrors []error
	for _, e := range entries {
		if !e.IsDir() || !generationName.MatchString(e.Name()) || e.Name() == current || e.Name() == previous {
			continue
		}
		if err := s.removeArtifacts(r.ID, e.Name()); err != nil {
			cleanupErrors = append(cleanupErrors, err)
		}
	}
	return errors.Join(cleanupErrors...)
}

func (s *Service) sameArtifacts(id string, old, next *model.Build) bool {
	if old == nil || len(old.Files) != len(next.Files) {
		return false
	}
	dir, err := s.artifactPath(id, old.Generation)
	if err != nil {
		return false
	}
	files := make(map[string]model.Artifact, len(old.Files))
	for _, f := range old.Files {
		files[f.Format] = f
	}
	for _, f := range next.Files {
		previous, ok := files[f.Format]
		if !ok || previous.SHA256 != f.SHA256 || previous.Size != f.Size {
			return false
		}
		info, err := os.Lstat(filepath.Join(dir, "rules."+Ext(f.Format)))
		if err != nil || !info.Mode().IsRegular() || info.Size() != int64(f.Size) {
			return false
		}
		file, err := os.Open(filepath.Join(dir, "rules."+Ext(f.Format)))
		if err != nil {
			return false
		}
		hash := sha256.New()
		n, readErr := io.Copy(hash, io.LimitReader(file, int64(f.Size)+1))
		closeErr := file.Close()
		if readErr != nil || closeErr != nil || n != int64(f.Size) || hex.EncodeToString(hash.Sum(nil)) != f.SHA256 {
			return false
		}
	}
	return true
}

func (s *Service) s3Target() string {
	c := s.Config.S3
	// Credentials may rotate without changing where the files are published.
	b, _ := json.Marshal([]any{c.Endpoint, c.Region, c.Bucket, c.Prefix, c.PublicURL, c.Secure, c.PathStyle})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
