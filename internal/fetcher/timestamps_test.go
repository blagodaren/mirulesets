package fetcher

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestCachedBodyKeepsFetchedAtUntilNewBody(t *testing.T) {
	var forceBody atomic.Bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"rules"` && !forceBody.Load() {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"rules"`)
		_, _ = w.Write([]byte("example.com\n"))
	}))
	defer upstream.Close()
	f := New(true)
	first, err := f.GetWithHeaders(context.Background(), upstream.URL, nil)
	if err != nil || first.HTTPStatus != http.StatusOK || first.FetchedAt.IsZero() {
		t.Fatalf("first download: %+v, %v", first, err)
	}
	// Seed a known past download time, independent of the platform clock's
	// resolution. This distinguishes revalidation from a body replacement.
	past := time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)
	f.mu.Lock()
	for key, cached := range f.cache {
		cached.fetchedAt = past
		f.cache[key] = cached
	}
	f.mu.Unlock()
	cached, err := f.GetWithHeaders(context.Background(), upstream.URL, nil)
	if err != nil || cached.HTTPStatus != http.StatusNotModified || !cached.FetchedAt.Equal(past) {
		t.Fatalf("304 changed original download time: %+v, %v", cached, err)
	}
	forceBody.Store(true)
	refreshed, err := f.GetWithHeaders(context.Background(), upstream.URL, nil)
	if err != nil || refreshed.HTTPStatus != http.StatusOK || !refreshed.FetchedAt.After(past) {
		t.Fatalf("200 did not replace original download time: %+v, %v", refreshed, err)
	}
	forceBody.Store(false)
	cached, err = f.GetWithHeaders(context.Background(), upstream.URL, nil)
	if err != nil || cached.HTTPStatus != http.StatusNotModified || !cached.FetchedAt.Equal(refreshed.FetchedAt) {
		t.Fatalf("304 lost refreshed download time: %+v, %v", cached, err)
	}
}
