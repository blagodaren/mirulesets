package config

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/blagodaren/mirulesets/internal/storage"
)

type Config struct {
	MetricsToken                                                           string
	RulesetsFile                                                           string
	SourceAllowedCIDRs                                                     []netip.Prefix
	Addr, DataDir, Password, APIToken, PublicURL                           string
	TLSMode, TLSAddr, HTTPAddr, Domain, ACMEEmail, ACMECA, TLSCert, TLSKey string
	AllowPrivateSources                                                    bool
	TrustedProxies                                                         []netip.Prefix
	S3                                                                     storage.Config
	AlertWebhookURL, AlertWebhookToken                                     string
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func Load() (Config, error) {
	c := Config{
		MetricsToken: os.Getenv("MI_METRICS_TOKEN"),
		RulesetsFile: os.Getenv("MI_RULESETS_FILE"),
		Addr:         env("MI_ADDR", "127.0.0.1:8080"), DataDir: env("MI_DATA_DIR", "data"),
		Password: os.Getenv("MI_ADMIN_PASSWORD"), APIToken: os.Getenv("MI_API_TOKEN"),
		PublicURL: strings.TrimRight(os.Getenv("MI_PUBLIC_URL"), "/"),
		TLSMode:   env("MI_TLS_MODE", "off"), TLSAddr: env("MI_TLS_ADDR", ":8443"),
		HTTPAddr: env("MI_HTTP_ADDR", ":8080"), Domain: os.Getenv("MI_DOMAIN"),
		ACMEEmail: os.Getenv("MI_ACME_EMAIL"), ACMECA: os.Getenv("MI_ACME_CA"),
		TLSCert: os.Getenv("MI_TLS_CERT"), TLSKey: os.Getenv("MI_TLS_KEY"),
		AllowPrivateSources: os.Getenv("MI_ALLOW_PRIVATE_SOURCES") == "true",
		AlertWebhookURL:     os.Getenv("MI_ALERT_WEBHOOK_URL"), AlertWebhookToken: os.Getenv("MI_ALERT_WEBHOOK_TOKEN"),
		S3: storage.Config{
			Endpoint: os.Getenv("MI_S3_ENDPOINT"), Region: env("MI_S3_REGION", "us-east-1"),
			Bucket: os.Getenv("MI_S3_BUCKET"), AccessKey: os.Getenv("MI_S3_ACCESS_KEY"),
			SecretKey: os.Getenv("MI_S3_SECRET_KEY"), SessionToken: os.Getenv("MI_S3_SESSION_TOKEN"),
			Prefix: env("MI_S3_PREFIX", "rules"), PublicURL: os.Getenv("MI_S3_PUBLIC_URL"),
			Secure: env("MI_S3_SECURE", "true") == "true", PathStyle: env("MI_S3_PATH_STYLE", "false") == "true",
		},
	}
	for _, raw := range strings.Split(os.Getenv("MI_TRUSTED_PROXIES"), ",") {
		if raw = strings.TrimSpace(raw); raw == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return c, fmt.Errorf("MI_TRUSTED_PROXIES: неверная CIDR подсеть %q", raw)
		}
		c.TrustedProxies = append(c.TrustedProxies, prefix)
	}
	for _, raw := range strings.Split(os.Getenv("MI_SOURCE_ALLOWED_CIDRS"), ",") {
		if raw = strings.TrimSpace(raw); raw == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return c, fmt.Errorf("MI_SOURCE_ALLOWED_CIDRS: неверная CIDR подсеть %q", raw)
		}
		c.SourceAllowedCIDRs = append(c.SourceAllowedCIDRs, prefix)
	}
	if err := os.MkdirAll(c.DataDir, 0700); err != nil {
		return c, err
	}
	if f := os.Getenv("MI_ADMIN_PASSWORD_FILE"); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return c, fmt.Errorf("password file: %w", err)
		}
		c.Password = strings.TrimSpace(string(b))
	}
	if c.Password == "" {
		f := filepath.Join(c.DataDir, "admin-password")
		b, err := os.ReadFile(f)
		if os.IsNotExist(err) {
			secret := make([]byte, 24)
			if _, err = rand.Read(secret); err != nil {
				return c, err
			}
			b = []byte(base64.RawURLEncoding.EncodeToString(secret))
			h, openErr := os.OpenFile(f, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if openErr != nil {
				return c, openErr
			}
			_, err = h.Write(b)
			closeErr := h.Close()
			if err == nil {
				err = closeErr
			}
		}
		if err != nil {
			return c, err
		}
		c.Password = strings.TrimSpace(string(b))
	}
	if len(c.Password) < 12 || len(c.Password) > 72 {
		return c, fmt.Errorf("MI_ADMIN_PASSWORD: требуется от 12 до 72 байт")
	}
	if c.APIToken != "" && len(c.APIToken) < 32 {
		return c, fmt.Errorf("MI_API_TOKEN: требуется не менее 32 символов")
	}
	if c.MetricsToken != "" {
		if utf8.RuneCountInString(c.MetricsToken) < 32 || strings.ContainsAny(c.MetricsToken, "\r\n") {
			return c, fmt.Errorf("MI_METRICS_TOKEN: требуется не менее 32 символов без переводов строк")
		}
		if c.MetricsToken == c.APIToken {
			return c, fmt.Errorf("MI_METRICS_TOKEN должен отличаться от MI_API_TOKEN")
		}
	}
	if c.AlertWebhookURL != "" {
		u, err := url.Parse(c.AlertWebhookURL)
		if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Fragment != "" {
			return c, fmt.Errorf("MI_ALERT_WEBHOOK_URL: нужен http(s) URL без userinfo и fragment")
		}
	}
	if strings.ContainsAny(c.AlertWebhookToken, "\r\n") {
		return c, fmt.Errorf("MI_ALERT_WEBHOOK_TOKEN: перевод строки недопустим")
	}
	if c.AlertWebhookToken != "" && c.AlertWebhookURL == "" {
		return c, fmt.Errorf("MI_ALERT_WEBHOOK_TOKEN: задайте MI_ALERT_WEBHOOK_URL")
	}
	switch c.TLSMode {
	case "off":
	case "auto":
		if c.Domain == "" || strings.ContainsAny(c.Domain, "/:* ") || !strings.Contains(c.Domain, ".") {
			return c, fmt.Errorf("MI_DOMAIN: требуется домен без протокола и порта")
		}
		if c.ACMEEmail == "" {
			return c, fmt.Errorf("MI_ACME_EMAIL обязателен для auto TLS")
		}
		if c.PublicURL == "" {
			c.PublicURL = "https://" + c.Domain
		}
	case "manual":
		if c.TLSCert == "" || c.TLSKey == "" {
			return c, fmt.Errorf("MI_TLS_CERT и MI_TLS_KEY обязательны для manual TLS")
		}
	default:
		return c, fmt.Errorf("MI_TLS_MODE: допустимы off, auto, manual")
	}
	if c.PublicURL != "" {
		u, err := url.Parse(c.PublicURL)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
			return c, fmt.Errorf("MI_PUBLIC_URL: нужен http(s) origin без пути")
		}
	}
	for _, key := range []string{"MI_ALLOW_PRIVATE_SOURCES", "MI_S3_SECURE", "MI_S3_PATH_STYLE"} {
		if v := os.Getenv(key); v != "" {
			if _, err := strconv.ParseBool(v); err != nil || (v != "true" && v != "false") {
				return c, fmt.Errorf("%s: true или false", key)
			}
		}
	}
	return c, nil
}
