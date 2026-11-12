package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStartupWarnsAboutSharedProxyLoginLimit(t *testing.T) {
	// Reuse httptest's local certificate so manual TLS startup needs no network.
	fixture := httptest.NewTLSServer(nil)
	certificate := fixture.TLS.Certificates[0]
	fixture.Close()
	key, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	certDir := t.TempDir()
	certPath, keyPath := filepath.Join(certDir, "cert.pem"), filepath.Join(certDir, "key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600); err != nil {
		t.Fatal(err)
	}
	previousArgs := os.Args
	os.Args = []string{"mirulesets"}
	t.Cleanup(func() { os.Args = previousArgs })
	for _, tc := range []struct {
		name, publicURL, tlsMode, trustedProxies string
		wantWarning                              bool
	}{
		{"external HTTPS", "https://rules.example.com", "off", "", true},
		{"uppercase HTTPS", "HTTPS://rules.example.com", "off", "", true},
		{"direct HTTP", "http://localhost:8080", "off", "", false},
		{"no public URL", "", "off", "", false},
		{"trusted proxy", "https://rules.example.com", "off", "127.0.0.1/32,::1/128", false},
		{"automatic TLS", "https://rules.example.com", "auto", "", false},
		{"manual TLS", "https://rules.example.com", "manual", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dataDir := t.TempDir()
			var logs bytes.Buffer
			previousLogger := slog.Default()
			slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
			t.Cleanup(func() { slog.SetDefault(previousLogger) })
			for name, value := range map[string]string{
				"MI_DATA_DIR": dataDir, "MI_ADMIN_PASSWORD": "test-password-12345", "MI_ADMIN_PASSWORD_FILE": "",
				"MI_ADDR": "127.0.0.1:0", "MI_TLS_ADDR": "127.0.0.1:0", "MI_HTTP_ADDR": "127.0.0.1:0",
				"MI_PUBLIC_URL": tc.publicURL, "MI_TLS_MODE": tc.tlsMode, "MI_TRUSTED_PROXIES": tc.trustedProxies,
				"MI_DOMAIN": "rules.example.com", "MI_ACME_EMAIL": "admin@example.com", "MI_ACME_CA": "",
				"MI_TLS_CERT": certPath, "MI_TLS_KEY": keyPath,
				"MI_API_TOKEN": "", "MI_METRICS_TOKEN": "", "MI_RULESETS_FILE": "",
				"MI_ALERT_WEBHOOK_URL": "", "MI_ALERT_WEBHOOK_TOKEN": "", "MI_SOURCE_ALLOWED_CIDRS": "",
				"MI_S3_BUCKET": "", "MI_S3_ENDPOINT": "", "MI_S3_ACCESS_KEY": "", "MI_S3_SECRET_KEY": "",
			} {
				t.Setenv(name, value)
			}
			// Exercise startup and its warning before immediately shutting down.
			// No TLS request is sent, so automatic TLS never contacts an ACME server.
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if err := runContext(ctx); err != nil {
				t.Fatalf("startup/shutdown: %v", err)
			}
			journal, err := os.ReadFile(filepath.Join(dataDir, "events.jsonl"))
			if err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			wantCount := 0
			if tc.wantWarning {
				wantCount = 1
			}
			for label, output := range map[string]string{"log": logs.String(), "event": string(journal)} {
				if got := strings.Count(output, "MI_TRUSTED_PROXIES пуст при внешнем HTTPS"); got != wantCount {
					t.Fatalf("%s: warning count = %d, want warning = %v", label, got, tc.wantWarning)
				}
				if tc.wantWarning {
					for _, fragment := range []string{"одним IP", "заблокировать вход всем", "только CIDR доверенных прокси", "warn"} {
						if !strings.Contains(strings.ToLower(output), strings.ToLower(fragment)) {
							t.Errorf("%s: warning missing %q", label, fragment)
						}
					}
				}
			}
		})
	}
}
