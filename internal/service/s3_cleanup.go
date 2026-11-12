package service

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/blagodaren/mirulesets/internal/model"
)

func (s *Service) cleanupS3Deletes(parent context.Context) error {
	s.cleanupMu.Lock()
	defer s.cleanupMu.Unlock()
	if s.S3 == nil {
		return nil
	}
	for _, id := range s.Store.PendingS3Deletes() {
		if s.Store.S3DeleteTarget(id) != s.s3Target() {
			return fmt.Errorf("цель S3 изменилась; очистка набора %s приостановлена до восстановления исходных настроек S3", id)
		}
		if !slug.MatchString(id) {
			return fmt.Errorf("некорректный ID в очереди очистки S3")
		}
		if _, exists := s.Store.Get(id); exists {
			return fmt.Errorf("нельзя очистить S3 существующего набора %s", id)
		}
		ctx, cancel := context.WithTimeout(parent, 30*time.Second)
		var failed bool
		for _, format := range []string{"yaml", "text", "mrs", "singbox", "srs"} {
			if err := s.S3.Delete(ctx, id+"."+Ext(format)); err != nil {
				failed = true
			}
		}
		cancel()
		if failed {
			return fmt.Errorf("не удалось удалить объекты S3 набора %s; очистка будет повторена", id)
		}
		if err := s.Store.Update(func(st *model.State) error {
			delete(st.S3DeleteTargets, id)
			st.PendingS3Deletes = slices.DeleteFunc(st.PendingS3Deletes, func(v string) bool { return v == id })
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}
