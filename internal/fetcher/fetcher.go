package fetcher

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

const MaxBytes = 32 << 20

var headerName = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")

// ValidateHeaders rejects transport controls and malformed values without ever
// putting a secret header name/value into an error string.
func ValidateHeaders(headers map[string]string) error {
	if len(headers) > 32 {
		return fmt.Errorf("не более 32 заголовков источника")
	}
	size := 0
	seen := map[string]bool{}
	for name, value := range headers {
		key := http.CanonicalHeaderKey(name)
		if !headerName.MatchString(name) || seen[key] {
			return fmt.Errorf("некорректное или повторяющееся имя заголовка источника")
		}
		seen[key] = true
		switch key {
		case "Host", "Connection", "Content-Length", "Transfer-Encoding", "Trailer", "Upgrade", "Proxy-Authorization", "Proxy-Connection", "Te", "Accept-Encoding", "If-None-Match", "If-Modified-Since", "Range":
			return fmt.Errorf("служебный HTTP-заголовок нельзя переопределять")
		}
		for _, c := range value {
			if c < 32 && c != '\t' || c == 127 {
				return fmt.Errorf("значение заголовка содержит управляющий символ")
			}
		}
		size += len(name) + len(value)
		if len(name) > 256 || len(value) > 8192 || size > 16<<10 {
			return fmt.Errorf("заголовки источника превышают лимит 16 KiB")
		}
	}
	return nil
}

type headerContextKey struct{}

type Result struct {
	Body       []byte
	HTTPStatus int
	FetchedAt  time.Time
}

type entry struct {
	body           []byte
	etag, modified string
	fetchedAt      time.Time
}
type Fetcher struct {
	client *http.Client
	mu     sync.Mutex
	cache  map[string]entry
	size   int
}

func AllowedIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, s := range []string{"100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001:db8::/32", "64:ff9b::/96", "64:ff9b:1::/48"} {
		if netip.MustParsePrefix(s).Contains(ip) {
			return false
		}
	}
	return true
}

func ValidateURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("некорректный URL")
	}
	if u.Scheme != "https" && u.Scheme != "http" && u.Scheme != "s3" {
		return fmt.Errorf("источник должен использовать https://, http:// или s3://")
	}
	if u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return fmt.Errorf("URL должен содержать хост, без логина и фрагмента")
	}
	if u.Scheme == "s3" && (u.Port() != "" || u.RawQuery != "" || strings.TrimPrefix(u.Path, "/") == "") {
		return fmt.Errorf("S3 URL: ожидается s3://bucket/key")
	}
	return nil
}

func New(allowPrivate bool, allowedCIDRs ...netip.Prefix) *Fetcher {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	tr := &http.Transport{MaxIdleConns: 64, MaxIdleConnsPerHost: 8, MaxConnsPerHost: 8, IdleConnTimeout: 90 * time.Second, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 15 * time.Second}
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, fmt.Errorf("DNS источника недоступен")
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("DNS источника не вернул адрес")
		}
		for _, ip := range ips {
			allowed := allowPrivate || AllowedIP(ip)
			for _, prefix := range allowedCIDRs {
				if prefix.Contains(ip.Unmap()) {
					allowed = true
				}
			}
			if !allowed {
				return nil, fmt.Errorf("DNS вернул приватный или служебный адрес; для доверенной сети задайте MI_SOURCE_ALLOWED_CIDRS")
			}
		}
		var last error
		for _, ip := range ips {
			conn, e := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if e == nil {
				return conn, nil
			}
			last = e
		}
		return nil, last
	}
	f := &Fetcher{cache: make(map[string]entry)}
	f.client = &http.Client{Transport: tr, Timeout: 45 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return fmt.Errorf("слишком много перенаправлений")
		}
		if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
			return fmt.Errorf("недопустимый протокол перенаправления")
		}
		if via[0].URL.Scheme == "https" && req.URL.Scheme == "http" {
			return fmt.Errorf("HTTPS источник перенаправляет на HTTP")
		}
		// net/http may copy initial headers again on each hop. Once any hop
		// leaves the original origin, no user-supplied header may be restored.
		crossOrigin := !sameOrigin(req.URL, via[0].URL)
		for _, prior := range via[1:] {
			crossOrigin = crossOrigin || !sameOrigin(prior.URL, via[0].URL)
		}
		if crossOrigin {
			if names, ok := req.Context().Value(headerContextKey{}).([]string); ok {
				for _, name := range names {
					req.Header.Del(name)
				}
			}
		}
		return ValidateURL(req.URL.String())
	}}
	return f
}

func (f *Fetcher) Get(ctx context.Context, raw string) ([]byte, error) {
	r, err := f.GetWithHeaders(ctx, raw, nil)
	return r.Body, err
}

func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Host, b.Host)
}

func (f *Fetcher) GetWithHeaders(ctx context.Context, raw string, headers map[string]string) (result Result, err error) {
	if err := ValidateURL(raw); err != nil {
		return result, err
	}
	if err := ValidateHeaders(headers); err != nil {
		return result, err
	}
	canonical := map[string]string{}
	names := make([]string, 0, len(headers))
	for name, value := range headers {
		name = http.CanonicalHeaderKey(name)
		canonical[name] = value
		names = append(names, name)
	}
	encoded, _ := json.Marshal(canonical)
	hash := sha256.Sum256(append(append([]byte(raw), 0), encoded...))
	cacheKey := hex.EncodeToString(hash[:])
	f.mu.Lock()
	cached, ok := f.cache[cacheKey]
	f.mu.Unlock()
	ctx = context.WithValue(ctx, headerContextKey{}, names)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return result, fmt.Errorf("некорректный запрос источника")
	}
	req.Header.Set("User-Agent", "MIRulesets/0.1 (+https://github.com/blagodaren/mirulesets)")
	for name, value := range canonical {
		req.Header.Set(name, value)
	}
	if ok {
		if cached.etag != "" {
			req.Header.Set("If-None-Match", cached.etag)
		}
		if cached.modified != "" {
			req.Header.Set("If-Modified-Since", cached.modified)
		}
	}
	resp, err := f.client.Do(req)
	if err != nil {
		var requestError *url.Error
		if errors.As(err, &requestError) {
			return result, fmt.Errorf("источник недоступен: %w", requestError.Err)
		}
		return result, fmt.Errorf("источник недоступен (сеть, TLS, тайм-аут или политика адресов)")
	}
	defer resp.Body.Close()
	result.HTTPStatus = resp.StatusCode
	if resp.StatusCode == http.StatusNotModified && ok {
		result.Body = append([]byte(nil), cached.body...)
		result.FetchedAt = cached.fetchedAt
		return result, nil
	}
	if resp.StatusCode != http.StatusOK {
		return result, fmt.Errorf("источник вернул HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > MaxBytes {
		return result, fmt.Errorf("источник превышает 32 MiB")
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxBytes+1))
	if err != nil {
		return result, fmt.Errorf("ошибка чтения источника")
	}
	if len(b) > MaxBytes {
		return result, fmt.Errorf("источник превышает 32 MiB")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.size+len(b) > 64<<20 {
		f.cache = make(map[string]entry)
		f.size = 0
	}
	if old, ok := f.cache[cacheKey]; ok {
		f.size -= len(old.body)
	}
	result.FetchedAt = time.Now().UTC()
	f.cache[cacheKey] = entry{body: append([]byte(nil), b...), etag: resp.Header.Get("ETag"), modified: resp.Header.Get("Last-Modified"), fetchedAt: result.FetchedAt}
	f.size += len(b)
	result.Body = b
	return result, nil
}
