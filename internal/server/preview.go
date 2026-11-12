package server

import (
	"context"
	"errors"
	"net/http"
	"time"
)

func (s *Server) preview(w http.ResponseWriter, r *http.Request) {
	select {
	case s.previewSlots <- struct{}{}:
		defer func() { <-s.previewSlots }()
	default:
		fail(w, http.StatusTooManyRequests, errors.New("одновременно доступны не более двух предпросмотров"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	var request struct {
		URL      string `json:"url"`
		Format   string `json:"format"`
		Behavior string `json:"behavior"`
	}
	if err := decode(w, r, &request); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	result, err := s.svc.PreviewSource(ctx, request.URL, request.Format, request.Behavior)
	if err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	respond(w, http.StatusOK, result)
}
