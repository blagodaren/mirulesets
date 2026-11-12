package main

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestStartupContinuesWhenS3CheckFails(t *testing.T) {
	var checks atomic.Int32
	s3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead && strings.TrimSuffix(r.URL.Path, "/") == "/rulesets" {
			checks.Add(1)
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer s3.Close()
	previousArgs := os.Args
	os.Args = []string{"mirulesets"}
	t.Cleanup(func() { os.Args = previousArgs })
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	dataDir := t.TempDir()
	var logs bytes.Buffer
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previousLogger) })
	for key, value := range map[string]string{
		"MI_DATA_DIR": dataDir, "MI_ADMIN_PASSWORD": "test-password-12345", "MI_ADMIN_PASSWORD_FILE": "",
		"MI_TLS_MODE": "off", "MI_ADDR": addr, "MI_API_TOKEN": "", "MI_METRICS_TOKEN": "",
		"MI_RULESETS_FILE": "", "MI_ALERT_WEBHOOK_URL": "", "MI_ALERT_WEBHOOK_TOKEN": "",
		"MI_PUBLIC_URL": "", "MI_TRUSTED_PROXIES": "", "MI_SOURCE_ALLOWED_CIDRS": "",
		"MI_S3_ENDPOINT": s3.URL, "MI_S3_BUCKET": "rulesets", "MI_S3_REGION": "us-east-1",
		"MI_S3_ACCESS_KEY": "test-access", "MI_S3_SECRET_KEY": "secret-must-not-leak",
		"MI_S3_SESSION_TOKEN": "", "MI_S3_PREFIX": "rules", "MI_S3_PUBLIC_URL": "", "MI_S3_PATH_STYLE": "true",
	} {
		t.Setenv(key, value)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- runContext(ctx) }()
	client := &http.Client{Timeout: 200 * time.Millisecond}
	started := false
	for ctx.Err() == nil {
		resp, err := client.Get("http://" + addr + "/healthz")
		if err == nil {
			started = resp.StatusCode == http.StatusOK
			_ = resp.Body.Close()
			if started {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("startup/shutdown: %v", err)
	}
	if !started {
		t.Fatal("local HTTP server did not start with unavailable S3")
	}
	if checks.Load() == 0 {
		t.Fatal("S3 bucket check was not called")
	}
	journal, err := os.ReadFile(filepath.Join(dataDir, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	const message = "S3 недоступен при запуске; локальная раздача работает, отправка будет повторена"
	for label, output := range map[string]string{"log": logs.String(), "event": string(journal)} {
		if !strings.Contains(output, message) || !strings.Contains(strings.ToLower(output), "warn") {
			t.Fatalf("%s lacks warning: %s", label, output)
		}
		if strings.Contains(output, "secret-must-not-leak") || strings.Contains(output, s3.URL) || strings.Contains(output, "bucket does not exist") {
			t.Fatalf("%s leaked S3 check details: %s", label, output)
		}
	}
}
