package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/blagodaren/mirulesets/internal/model"
)

const (
	eventLogMaxBytes     = 1 << 20
	eventHistorySize     = 100
	eventMessageMaxBytes = 16 << 10
	alertTimeout         = 5 * time.Second
)

type eventJournal struct {
	mu     sync.Mutex
	path   string
	events []model.Event
	client *http.Client
}

func (s *Service) initEvents() error {
	j := &eventJournal{
		path:   filepath.Join(s.Config.DataDir, "events.jsonl"),
		events: []model.Event{},
		client: &http.Client{
			Timeout: alertTimeout,
			// A redirect must not forward webhook secrets to another endpoint.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
	for _, path := range []string{j.path + ".1", j.path} {
		if err := j.load(path); err != nil {
			return fmt.Errorf("журнал событий: %w", err)
		}
	}
	s.journal = j
	return nil
}

func (j *eventJournal) load(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0600)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, eventLogMaxBytes+1))
	if err != nil {
		return err
	}
	if len(b) > eventLogMaxBytes {
		return fmt.Errorf("%s превышает лимит 1 MiB", filepath.Base(path))
	}
	// An interrupted append may leave a partial last record. Remove it before
	// appending again, so it cannot swallow the next complete event.
	end := bytes.LastIndexByte(b, '\n') + 1
	if end < len(b) {
		if err = f.Truncate(int64(end)); err != nil {
			return err
		}
		if err = f.Sync(); err != nil {
			return err
		}
	}
	for _, line := range bytes.Split(b[:end], []byte{'\n'}) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var event model.Event
		if err = json.Unmarshal(line, &event); err != nil {
			return fmt.Errorf("%s содержит повреждённую запись", filepath.Base(path))
		}
		j.remember(event)
	}
	return nil
}

func (j *eventJournal) remember(event model.Event) {
	j.events = append([]model.Event{event}, j.events...)
	if len(j.events) > eventHistorySize {
		j.events = j.events[:eventHistorySize]
	}
}

func boundedEvent(event model.Event) model.Event {
	event.Message = strings.ToValidUTF8(event.Message, "�")
	if len(event.Message) > eventMessageMaxBytes {
		end := eventMessageMaxBytes
		for !utf8.RuneStart(event.Message[end]) {
			end--
		}
		event.Message = event.Message[:end] + "… [сообщение сокращено]"
	}
	return event
}

func (j *eventJournal) append(event model.Event) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.remember(event)
	b, err := json.Marshal(event)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if st, statErr := os.Stat(j.path); statErr == nil {
		if st.Size()+int64(len(b)) > eventLogMaxBytes {
			if err = os.Rename(j.path, j.path+".1"); err != nil {
				return err
			}
		}
	} else if !os.IsNotExist(statErr) {
		return statErr
	}
	f, err := os.OpenFile(j.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	start, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		_ = f.Close()
		return err
	}
	_, err = f.Write(b)
	if err != nil {
		// A partial write (for example, a full disk) must not corrupt the next
		// record if this process keeps running and space becomes available.
		truncateErr := f.Truncate(start)
		syncErr := f.Sync()
		return errors.Join(err, truncateErr, syncErr, f.Close())
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	return err
}

func (s *Service) Event(level, message, id string) {
	event := boundedEvent(model.Event{Time: time.Now().UTC(), Level: level, Message: message, RulesetID: id})
	if err := s.journal.append(event); err != nil {
		slog.Error("Не удалось сохранить событие", "error", err, "ruleset", id)
	}
	if level != "error" || s.Config.AlertWebhookURL == "" {
		return
	}
	if err := s.sendAlert(event); err != nil {
		// Delivery failures are journaled without recursively sending alerts.
		warning := model.Event{Time: time.Now().UTC(), Level: "warning", Message: err.Error(), RulesetID: id}
		if journalErr := s.journal.append(warning); journalErr != nil {
			slog.Error("Не удалось сохранить сбой webhook", "error", journalErr, "ruleset", id)
		}
		slog.Warn(warning.Message, "ruleset", id)
	}
}

func (s *Service) Events() []model.Event {
	s.journal.mu.Lock()
	defer s.journal.mu.Unlock()
	return append([]model.Event{}, s.journal.events...)
}

func (s *Service) sendAlert(event model.Event) error {
	b, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("Webhook: не удалось подготовить событие")
	}
	ctx, cancel := context.WithTimeout(context.Background(), alertTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.Config.AlertWebhookURL, bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("Webhook: некорректная конфигурация запроса")
	}
	req.Header.Set("Content-Type", "application/json")
	if s.Config.AlertWebhookToken != "" {
		req.Header.Set("Authorization", "Bearer "+s.Config.AlertWebhookToken)
	}
	res, err := s.journal.client.Do(req)
	if err != nil {
		// net/http errors may include the complete URL, including credentials.
		return fmt.Errorf("Webhook: ошибка сети или превышен тайм-аут 5 секунд")
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("Webhook: сервер вернул HTTP %d", res.StatusCode)
	}
	return nil
}
