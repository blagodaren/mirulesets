package server

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/blagodaren/mirulesets/internal/model"
	"github.com/blagodaren/mirulesets/internal/service"
	"github.com/blagodaren/mirulesets/internal/version"
	"github.com/blagodaren/mirulesets/web"
	"go.yaml.in/yaml/v3"
	"golang.org/x/crypto/bcrypt"
)

type attempt struct {
	count int
	until time.Time
}
type Server struct {
	svc          *service.Service
	hash         []byte
	mu           sync.Mutex
	sessions     map[string]time.Time
	attempts     map[string]attempt
	loginSlots   chan struct{}
	previewSlots chan struct{}
	downloads    map[string]uint64
}

func New(svc *service.Service) (http.Handler, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(svc.Config.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	s := &Server{svc: svc, hash: hash, sessions: map[string]time.Time{}, attempts: map[string]attempt{}, loginSlots: make(chan struct{}, 4), previewSlots: make(chan struct{}, 2), downloads: map[string]uint64{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { respond(w, 200, map[string]string{"status": "ok"}) })
	mux.Handle("GET /metrics", s.protectMetrics(http.HandlerFunc(s.metrics)))
	mux.HandleFunc("GET /api/session", func(w http.ResponseWriter, r *http.Request) {
		respond(w, 200, map[string]bool{"authenticated": s.authenticated(r)})
	})
	mux.HandleFunc("POST /api/login", s.login)
	mux.Handle("/api/", s.protect(http.HandlerFunc(s.api)))
	mux.HandleFunc("GET /rules/{file}", s.artifact)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" && r.Method != "HEAD" {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", 405)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/")
		if name == "" {
			name = "index.html"
		}
		if !slices.Contains([]string{
			"index.html", "app.js", "theme.js", "styles.css", "favicon.svg",
			"fonts/geist-cyrillic-wght-normal.woff2",
			"fonts/geist-latin-wght-normal.woff2",
			"fonts/geist-mono-cyrillic-wght-normal.woff2",
			"fonts/geist-mono-latin-wght-normal.woff2",
			"licenses/geist-LICENSE.txt", "licenses/geist-mono-LICENSE.txt",
			"licenses/fonts-NOTICE.txt", "licenses/miboard-NOTICE.txt",
		}, name) {
			http.NotFound(w, r)
			return
		}
		b, err := fs.ReadFile(web.Files, name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		switch filepath.Ext(name) {
		case ".js":
			w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		case ".css":
			w.Header().Set("Content-Type", "text/css; charset=utf-8")
		case ".svg":
			w.Header().Set("Content-Type", "image/svg+xml")
		case ".woff2":
			w.Header().Set("Content-Type", "font/woff2")
		case ".txt":
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		default:
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
		}
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("ETag", fmt.Sprintf(`"%x"`, sha256.Sum256(b)))
		http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(b))
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
		if r.TLS != nil || strings.HasPrefix(svc.Config.PublicURL, "https://") {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		if strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/metrics" {
			w.Header().Set("Cache-Control", "no-store")
		}
		mux.ServeHTTP(w, r)
	}), nil
}

func respond(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, err error) {
	respond(w, status, map[string]string{"error": err.Error()})
}
func decode(w http.ResponseWriter, r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
	d := json.NewDecoder(r.Body)
	if err := d.Decode(v); err != nil {
		return fmt.Errorf("неверный JSON или превышен лимит 4 MiB")
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return fmt.Errorf("ожидается один JSON объект")
	}
	return nil
}

func (s *Server) bearer(r *http.Request) bool {
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		return false
	}
	v := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	return s.svc.Config.APIToken != "" && r.Header.Get("Authorization") != "" && subtle.ConstantTimeCompare([]byte(v), []byte(s.svc.Config.APIToken)) == 1
}
func (s *Server) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	trusted := func(ip netip.Addr) bool {
		for _, network := range s.svc.Config.TrustedProxies {
			if network.Contains(ip.Unmap()) {
				return true
			}
		}
		return false
	}
	if !trusted(peer) {
		return host
	}
	chain := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(chain) - 1; i >= 0; i-- {
		ip, err := netip.ParseAddr(strings.TrimSpace(chain[i]))
		if err != nil {
			return host
		}
		if !trusted(ip) {
			return ip.Unmap().String()
		}
	}
	return host
}

func (s *Server) authenticated(r *http.Request) bool {
	if s.bearer(r) {
		return true
	}
	c, err := r.Cookie("mi_session")
	if err != nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	expiry, ok := s.sessions[c.Value]
	if ok && time.Now().Before(expiry) {
		return true
	}
	delete(s.sessions, c.Value)
	return false
}
func (s *Server) sameOrigin(r *http.Request) bool {
	if s.bearer(r) {
		return true
	}
	if r.Header.Get("X-Requested-With") != "MIRulesets" {
		return false
	}
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	if origin == s.svc.Config.PublicURL {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return u.Host == r.Host && u.Scheme == scheme
}
func (s *Server) protect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.authenticated(r) {
			fail(w, 401, errors.New("требуется вход"))
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" && !s.sameOrigin(r) {
			fail(w, 403, errors.New("недопустимый источник запроса"))
			return
		}
		next.ServeHTTP(w, r)
	})
}
func (s *Server) cookie(w http.ResponseWriter, r *http.Request, token string, age int) {
	http.SetCookie(w, &http.Cookie{Name: "mi_session", Value: token, Path: "/", MaxAge: age, HttpOnly: true, Secure: r.TLS != nil || strings.HasPrefix(s.svc.Config.PublicURL, "https://"), SameSite: http.SameSiteStrictMode})
}
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if !s.sameOrigin(r) {
		fail(w, 403, errors.New("недопустимый источник запроса"))
		return
	}
	ip := s.clientIP(r)
	now := time.Now()
	s.mu.Lock()
	a := s.attempts[ip]
	if now.After(a.until) {
		a = attempt{until: now.Add(15 * time.Minute)}
	}
	a.count++
	s.attempts[ip] = a
	if len(s.attempts) > 10000 {
		for k, v := range s.attempts {
			if now.After(v.until) {
				delete(s.attempts, k)
			}
		}
	}
	s.mu.Unlock()
	if a.count > 10 {
		w.Header().Set("Retry-After", "900")
		fail(w, 429, errors.New("слишком много попыток входа; повторите через 15 минут"))
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if err := decode(w, r, &body); err != nil {
		fail(w, 400, err)
		return
	}
	select {
	case s.loginSlots <- struct{}{}:
		defer func() { <-s.loginSlots }()
	default:
		fail(w, 429, errors.New("повторите вход через несколько секунд"))
		return
	}
	if len(body.Password) > 72 || bcrypt.CompareHashAndPassword(s.hash, []byte(body.Password)) != nil {
		fail(w, 401, errors.New("неверный пароль"))
		return
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		fail(w, 500, errors.New("не удалось создать сессию"))
		return
	}
	token := base64.RawURLEncoding.EncodeToString(b)
	s.mu.Lock()
	delete(s.attempts, ip)
	for k, v := range s.sessions {
		if now.After(v) {
			delete(s.sessions, k)
		}
	}
	if len(s.sessions) >= 64 {
		for k := range s.sessions {
			delete(s.sessions, k)
			break
		}
	}
	s.sessions[token] = now.Add(24 * time.Hour)
	s.mu.Unlock()
	s.cookie(w, r, token, 86400)
	respond(w, 200, map[string]bool{"authenticated": true})
}

func (s *Server) system() map[string]any {
	return map[string]any{"version": version.Version, "tlsMode": s.svc.Config.TLSMode, "publicUrl": s.svc.Config.PublicURL, "s3Enabled": s.svc.S3 != nil, "s3Bucket": s.svc.Config.S3.Bucket, "s3PublicUrl": s.svc.Config.S3.PublicURL}
}

func (s *Server) api(w http.ResponseWriter, r *http.Request) {
	p := strings.TrimPrefix(r.URL.Path, "/api/")
	if s.extendedAPI(w, r, p) {
		return
	}
	if p == "logout" && r.Method == "POST" {
		if c, e := r.Cookie("mi_session"); e == nil {
			s.mu.Lock()
			delete(s.sessions, c.Value)
			s.mu.Unlock()
		}
		s.cookie(w, r, "", -1)
		respond(w, 200, map[string]bool{"authenticated": false})
		return
	}
	if p == "overview" && r.Method == "GET" {
		sets := redactRulesets(s.svc.Store.List())
		stats := map[string]int{"rulesets": len(sets), "sources": 0, "rules": 0, "storageBytes": 0}
		for _, set := range sets {
			stats["sources"] += len(set.Sources)
			if set.LastBuild != nil {
				stats["rules"] += set.LastBuild.RuleCount
				for _, file := range set.LastBuild.Files {
					stats["storageBytes"] += file.Size
				}
			}
		}
		respond(w, 200, map[string]any{"rulesets": sets, "stats": stats, "system": s.system(), "activity": s.svc.Events(), "downloads": s.downloadCounts()})
		return
	}
	if p == "system" && r.Method == "GET" {
		respond(w, 200, map[string]any{"system": s.system()})
		return
	}
	if p == "preview" && r.Method == "POST" {
		s.preview(w, r)
		return
	}
	if p == "rulesets" {
		if r.Method == "GET" {
			respond(w, 200, map[string]any{"rulesets": redactRulesets(s.svc.Store.List())})
			return
		}
		if r.Method == "POST" {
			var body model.Ruleset
			if err := decode(w, r, &body); err != nil {
				fail(w, 400, err)
				return
			}
			result, err := s.svc.Save(body, true)
			if err != nil {
				s.serviceError(w, err)
				return
			}
			respond(w, 201, map[string]any{"ruleset": service.RedactRuleset(result)})
			return
		}
	}
	parts := strings.Split(p, "/")
	if len(parts) >= 2 && parts[0] == "rulesets" {
		id := parts[1]
		if len(parts) == 2 {
			switch r.Method {
			case "GET":
				set, ok := s.svc.Store.Get(id)
				if !ok {
					s.serviceError(w, service.ErrNotFound)
					return
				}
				respond(w, 200, map[string]any{"ruleset": service.RedactRuleset(set)})
				return
			case "PUT":
				var body model.Ruleset
				if err := decode(w, r, &body); err != nil {
					fail(w, 400, err)
					return
				}
				if body.ID != id {
					fail(w, 400, errors.New("ID набора нельзя изменить"))
					return
				}
				result, err := s.svc.Save(body, false)
				if err != nil {
					s.serviceError(w, err)
					return
				}
				respond(w, 200, map[string]any{"ruleset": service.RedactRuleset(result)})
				return
			case "DELETE":
				if err := s.svc.Delete(id); err != nil {
					s.serviceError(w, err)
					return
				}
				s.mu.Lock()
				delete(s.downloads, id)
				s.mu.Unlock()
				respond(w, 200, map[string]bool{"deleted": true})
				return
			}
		}
		if len(parts) == 3 && parts[2] == "build" && r.Method == "POST" {
			result, err := s.svc.Build(r.Context(), id)
			if err != nil {
				s.serviceError(w, err)
				return
			}
			respond(w, 200, map[string]any{"ruleset": service.RedactRuleset(result)})
			return
		}
		if len(parts) == 3 && parts[2] == "snippet" && r.Method == "GET" {
			s.snippet(w, r, id)
			return
		}
	}
	fail(w, 404, errors.New("маршрут не найден"))
}

func (s *Server) serviceError(w http.ResponseWriter, err error) {
	status := 400
	if errors.Is(err, service.ErrNotFound) {
		status = 404
	}
	if errors.Is(err, service.ErrConflict) || errors.Is(err, service.ErrBusy) {
		status = 409
	}
	var pe *os.PathError
	if errors.As(err, &pe) {
		status = 500
		err = errors.New("ошибка хранилища; проверьте свободное место и права каталога данных")
	}
	fail(w, status, err)
}

func (s *Server) artifact(w http.ResponseWriter, r *http.Request) {
	file := r.PathValue("file")
	dot := strings.LastIndex(file, ".")
	if dot < 1 {
		http.NotFound(w, r)
		return
	}
	id, ext := file[:dot], file[dot+1:]
	format := ext
	if ext == "txt" || ext == "list" {
		format = "text"
	}
	if ext == "yml" {
		format = "yaml"
	}
	if ext == "json" {
		format = "singbox"
	}
	build, ok := s.svc.Store.Publication(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	var item *model.Artifact
	for i := range build.Files {
		if build.Files[i].Format == format {
			item = &build.Files[i]
			break
		}
	}
	if item == nil {
		http.NotFound(w, r)
		return
	}
	f, err := os.Open(filepath.Join(s.svc.Config.DataDir, "artifacts", id, build.Generation, "rules."+service.Ext(format)))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", service.ContentType(format))
	w.Header().Set("ETag", `"`+item.SHA256+`"`)
	w.Header().Set("Cache-Control", "public, max-age=60, must-revalidate")
	counted := &downloadResponse{ResponseWriter: w}
	http.ServeContent(counted, r, file, build.BuiltAt, f)
	if r.Method == http.MethodGet && (counted.status == 200 || counted.status == 206) && counted.bytes > 0 {
		s.mu.Lock()
		s.downloads[id]++
		s.mu.Unlock()
	}
}

func (s *Server) snippet(w http.ResponseWriter, r *http.Request, id string) {
	set, ok := s.svc.Store.Get(id)
	if !ok {
		s.serviceError(w, service.ErrNotFound)
		return
	}
	if set.LastBuild == nil || set.LastBuild.Revision != set.Revision {
		fail(w, 409, errors.New("сначала успешно соберите текущую версию набора"))
		return
	}
	format := r.URL.Query().Get("format")
	if format == "" {
		format = set.Formats[0]
	}
	if !slices.Contains(set.Formats, format) {
		fail(w, 400, errors.New("формат не включён для этого набора"))
		return
	}
	if !slices.Contains([]string{"yaml", "text", "mrs"}, format) {
		fail(w, 400, errors.New("для Mihomo выберите YAML, text или MRS"))
		return
	}
	base := s.svc.Config.PublicURL
	if base == "" {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		base = scheme + "://" + r.Host
	}
	policy := set.Policy
	if policy == "" {
		policy = "PROXY"
	}
	data := map[string]any{"rule-providers": map[string]any{id: map[string]any{"type": "http", "behavior": set.Behavior, "format": format, "url": base + "/rules/" + id + "." + service.Ext(format), "path": "./ruleset/" + id + "." + service.Ext(format), "interval": set.IntervalSeconds}}, "rules": []string{"RULE-SET," + id + "," + policy}}
	b, err := yaml.Marshal(data)
	if err != nil {
		fail(w, 500, errors.New("не удалось сформировать YAML"))
		return
	}
	respond(w, 200, map[string]string{"yaml": string(b)})
}
