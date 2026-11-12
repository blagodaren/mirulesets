package service

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blagodaren/mirulesets/internal/config"
	"github.com/blagodaren/mirulesets/internal/model"
)

func eventService(t *testing.T, c config.Config) *Service {
	t.Helper()
	if c.DataDir == "" {
		c.DataDir = t.TempDir()
	}
	s := &Service{Config: c}
	if err := s.initEvents(); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestEventsPersistAndRecoverPartialAppend(t *testing.T) {
	c := config.Config{DataDir: t.TempDir()}
	s := eventService(t, c)
	s.Event("info", "first", "example")
	s.Event("error", "source unavailable", "example")
	path := filepath.Join(c.DataDir, "events.jsonl")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.WriteString(`{"time":"incomplete`); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := eventService(t, c)
	if events := reopened.Events(); len(events) != 2 || events[0].Message != "source unavailable" || events[1].Message != "first" {
		t.Fatalf("restored events: %+v", events)
	}
	reopened.Event("success", "recovered", "example")
	if events := eventService(t, c).Events(); len(events) != 3 || events[0].Message != "recovered" {
		t.Fatalf("append after truncated record: %+v", events)
	}
}

func TestEventRotationAndBoundedHistory(t *testing.T) {
	s := eventService(t, config.Config{})
	// Force several rotations, including replacement of an existing archive.
	for i := 0; i < 180; i++ {
		s.Event("info", strings.Repeat("я", eventMessageMaxBytes), "example")
	}
	s.Event("success", "last", "example")
	for _, path := range []string{s.journal.path, s.journal.path + ".1"} {
		st, err := os.Stat(path)
		if err != nil || st.Size() > eventLogMaxBytes {
			t.Fatalf("unbounded/missing journal %s: %v, %v", path, st, err)
		}
	}
	if got := s.Events(); len(got) != eventHistorySize || got[0].Message != "last" {
		t.Fatalf("in-memory history: %d", len(got))
	}
	reopened := eventService(t, s.Config)
	if got := reopened.Events(); len(got) != eventHistorySize || got[0].Message != "last" {
		t.Fatalf("restored history: %d", len(got))
	}
	copy := reopened.Events()
	copy[0].Message = "changed"
	if reopened.Events()[0].Message != "last" {
		t.Fatal("Events exposes mutable history")
	}
}

func TestEventAppendFailureStillKeepsMemory(t *testing.T) {
	s := eventService(t, config.Config{})
	if err := os.Mkdir(s.journal.path, 0700); err != nil {
		t.Fatal(err)
	}
	s.Event("error", "build failed", "example")
	if got := s.Events(); len(got) != 1 || got[0].Message != "build failed" {
		t.Fatalf("failure lost from memory: %+v", got)
	}
}

func TestWebhookOnlySendsErrorsWithBearerToken(t *testing.T) {
	var requests atomic.Int32
	payloads := make(chan model.Event, 1)
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Authorization") != "Bearer receiver-secret" {
			t.Errorf("unexpected webhook request: %s %v", r.Method, r.Header)
		}
		var payload model.Event
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Error(err)
		}
		payloads <- payload
		w.WriteHeader(http.StatusNoContent)
	}))
	defer endpoint.Close()
	s := eventService(t, config.Config{AlertWebhookURL: endpoint.URL, AlertWebhookToken: "receiver-secret"})
	s.Event("info", "started", "example")
	s.Event("success", "ready", "example")
	s.Event("error", "upstream returned 503", "example")
	received := <-payloads
	if requests.Load() != 1 || received.RulesetID != "example" || received.Level != "error" || received.Message != "upstream returned 503" || received.Time.IsZero() {
		t.Fatalf("webhook requests=%d payload=%+v", requests.Load(), received)
	}
}

func TestWebhookRejectsRedirectAndJournalsFailure(t *testing.T) {
	var redirected atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1) }))
	defer target.Close()
	var requests atomic.Int32
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer endpoint.Close()
	s := eventService(t, config.Config{AlertWebhookURL: endpoint.URL + "?secret=hidden", AlertWebhookToken: "hidden-token"})
	s.Event("error", "failed", "example")
	if requests.Load() != 1 || redirected.Load() != 0 {
		t.Fatalf("redirect followed or recursive alert: requests=%d redirected=%d", requests.Load(), redirected.Load())
	}
	events := eventService(t, s.Config).Events()
	if len(events) != 2 || events[0].Level != "warning" || events[0].Message != "Webhook: сервер вернул HTTP 307" || events[1].Level != "error" {
		t.Fatalf("delivery failure not journaled: %+v", events)
	}
}

type alertTransport func(*http.Request) (*http.Response, error)

func (f alertTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestWebhookNetworkErrorRedactsURLAndHasDeadline(t *testing.T) {
	s := eventService(t, config.Config{AlertWebhookURL: "https://example.invalid/token-in-path?secret=hidden"})
	s.journal.client.Transport = alertTransport(func(r *http.Request) (*http.Response, error) {
		deadline, ok := r.Context().Deadline()
		if !ok || time.Until(deadline) > alertTimeout || s.journal.client.Timeout != alertTimeout {
			t.Error("webhook has no bounded timeout")
		}
		return nil, errors.New("connection failure at " + r.URL.String())
	})
	s.Event("error", "build failed", "example")
	for _, event := range s.Events() {
		if strings.Contains(event.Message, "hidden") || strings.Contains(event.Message, "token-in-path") {
			t.Fatalf("webhook credential leaked: %s", event.Message)
		}
	}
	if events := s.Events(); len(events) != 2 || events[0].Level != "warning" {
		t.Fatalf("missing delivery failure: %+v", events)
	}
}

func TestConcurrentEventWrites(t *testing.T) {
	s := eventService(t, config.Config{})
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.Event("info", "concurrent", "example")
			_ = s.Events()
		}()
	}
	wg.Wait()
	if got := eventService(t, s.Config).Events(); len(got) != 20 {
		t.Fatalf("lost concurrent events: %d", len(got))
	}
}
