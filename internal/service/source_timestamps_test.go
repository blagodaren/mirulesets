package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/blagodaren/mirulesets/internal/config"
	"github.com/blagodaren/mirulesets/internal/model"
)

func TestSourceFetchedAtTracksBodyInsteadOfConditionalChecks(t *testing.T) {
	var forceBody atomic.Bool
	var fail atomic.Bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if r.Header.Get("If-None-Match") == `"rules"` && !forceBody.Load() {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"rules"`)
		_, _ = w.Write([]byte("example.com\n"))
	}))
	defer upstream.Close()
	s, err := New(config.Config{DataDir: t.TempDir(), AllowPrivateSources: true})
	if err != nil {
		t.Fatal(err)
	}
	src := model.Source{URL: upstream.URL, Format: "text", Behavior: "domain"}
	_, first, err := s.sourceWithStatus(context.Background(), src)
	if err != nil || first.HTTPStatus != http.StatusOK || first.FetchedAt.IsZero() {
		t.Fatalf("first download: %+v, %v", first, err)
	}
	// A new source can use a cache warmed by another source or preview. It has
	// no previous status from which to recover the original download time.
	_, cached, err := s.sourceWithStatus(context.Background(), src)
	if err != nil || cached.HTTPStatus != http.StatusNotModified || !cached.FetchedAt.Equal(first.FetchedAt) || cached.CheckedAt.Before(first.CheckedAt) {
		t.Fatalf("cached check changed download time: first=%+v cached=%+v err=%v", first, cached, err)
	}
	src.Status = &cached
	forceBody.Store(true)
	_, refreshed, err := s.sourceWithStatus(context.Background(), src)
	// Windows can return equal wall-clock values for consecutive requests.
	// The fetcher test separately proves replacement of an older cache timestamp.
	if err != nil || refreshed.HTTPStatus != http.StatusOK || refreshed.FetchedAt.Before(cached.FetchedAt) || refreshed.FetchedAt.Before(refreshed.CheckedAt) {
		t.Fatalf("new body did not update download time: %+v, %v", refreshed, err)
	}
	src.Status = &refreshed
	fail.Store(true)
	_, failed, err := s.sourceWithStatus(context.Background(), src)
	if err == nil || failed.HTTPStatus != http.StatusServiceUnavailable || !failed.FetchedAt.Equal(refreshed.FetchedAt) {
		t.Fatalf("failed check lost last download time: %+v, %v", failed, err)
	}
}
