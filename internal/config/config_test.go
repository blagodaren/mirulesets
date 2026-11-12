package config

import (
	"strings"
	"testing"
)

func testConfigEnvironment(t *testing.T) {
	t.Helper()
	for _, name := range []string{"MI_ADMIN_PASSWORD_FILE", "MI_API_TOKEN", "MI_METRICS_TOKEN", "MI_PUBLIC_URL", "MI_ALERT_WEBHOOK_URL", "MI_ALERT_WEBHOOK_TOKEN", "MI_TRUSTED_PROXIES", "MI_SOURCE_ALLOWED_CIDRS", "MI_ALLOW_PRIVATE_SOURCES", "MI_S3_SECURE", "MI_S3_PATH_STYLE", "MI_S3_PREFIX"} {
		t.Setenv(name, "")
	}
	t.Setenv("MI_TLS_MODE", "off")
	t.Setenv("MI_ADMIN_PASSWORD", "test-password-123")
	t.Setenv("MI_DATA_DIR", t.TempDir())
}

func TestMetricsTokenConfiguration(t *testing.T) {
	for _, tt := range []struct {
		name, token, api string
		invalid          bool
	}{
		{name: "unset"},
		{name: "valid", token: strings.Repeat("m", 32), api: strings.Repeat("a", 32)},
		{name: "short", token: strings.Repeat("m", 31), invalid: true},
		{name: "short-unicode", token: strings.Repeat("я", 16), invalid: true},
		{name: "newline", token: strings.Repeat("m", 32) + "\n", invalid: true},
		{name: "carriage-return", token: strings.Repeat("m", 32) + "\r", invalid: true},
		{name: "same-api", token: strings.Repeat("m", 32), api: strings.Repeat("m", 32), invalid: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			testConfigEnvironment(t)
			t.Setenv("MI_METRICS_TOKEN", tt.token)
			t.Setenv("MI_API_TOKEN", tt.api)
			c, err := Load()
			if (err != nil) != tt.invalid {
				t.Fatalf("Load: %v, expected invalid=%t", err, tt.invalid)
			}
			if err != nil && strings.Contains(err.Error(), tt.token) {
				t.Fatal("validation disclosed token")
			}
			if err == nil && c.MetricsToken != tt.token {
				t.Fatal("metrics token was not loaded")
			}
		})
	}
}

func TestAlertWebhookConfiguration(t *testing.T) {
	tests := []struct {
		name, url, token string
		wantError        bool
	}{
		{name: "disabled"},
		{name: "https", url: "https://hooks.example.com/build?token=secret", token: "bearer-secret"},
		{name: "http-local", url: "http://127.0.0.1:8081/hooks"},
		{name: "invalid-scheme", url: "file:///etc/passwd", wantError: true},
		{name: "missing-host", url: "http:///hook", wantError: true},
		{name: "userinfo", url: "https://user:secret@example.com", wantError: true},
		{name: "fragment", url: "https://example.com/#secret", wantError: true},
		{name: "invalid-escape", url: "https://example.com/%secret", wantError: true},
		{name: "header-injection", url: "https://example.com", token: "secret\r\nX-Injected: yes", wantError: true},
		{name: "token-without-url", token: "secret", wantError: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testConfigEnvironment(t)
			t.Setenv("MI_ALERT_WEBHOOK_URL", tt.url)
			t.Setenv("MI_ALERT_WEBHOOK_TOKEN", tt.token)
			c, err := Load()
			if (err != nil) != tt.wantError {
				t.Fatalf("Load error=%v, expected error=%v", err, tt.wantError)
			}
			if err != nil && strings.Contains(err.Error(), "secret") {
				t.Fatalf("config error leaked secret: %v", err)
			}
			if err == nil && (c.AlertWebhookURL != tt.url || c.AlertWebhookToken != tt.token || c.S3.Prefix != "rules") {
				t.Fatal("configuration did not preserve webhook/default prefix")
			}
		})
	}
}
