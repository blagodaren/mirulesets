package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/blagodaren/mirulesets/internal/fetcher"
	"github.com/blagodaren/mirulesets/internal/model"
	"github.com/blagodaren/mirulesets/internal/rules"
)

// ValidateSource is shared by API saves and declarative configuration imports.
func ValidateSource(src *model.Source, defaultBehavior string) error {
	src.URL = strings.TrimSpace(src.URL)
	src.Name = strings.TrimSpace(src.Name)
	if len(src.URL) > 8192 || len(src.Name) > 160 {
		return fmt.Errorf("слишком длинный адрес или название источника")
	}
	if src.ID == "" {
		var id [12]byte
		if _, err := rand.Read(id[:]); err != nil {
			return err
		}
		src.ID = hex.EncodeToString(id[:])
	} else if !slug.MatchString(src.ID) {
		return fmt.Errorf("некорректный ID источника")
	}
	if src.Format == "" {
		src.Format = "auto"
	}
	if !slices.Contains([]string{"auto", "yaml", "text", "mrs", "geosite", "geoip", "hosts", "adblock", "singbox", "asn"}, src.Format) {
		return fmt.Errorf("неизвестный формат источника")
	}
	if src.Behavior == "" {
		src.Behavior = defaultBehavior
	}
	if !slices.Contains([]string{"domain", "ipcidr", "classical"}, src.Behavior) {
		return fmt.Errorf("неизвестный behavior источника")
	}
	if src.Format == "mrs" && src.Behavior == "classical" {
		return fmt.Errorf("MRS несовместим с classical")
	}
	if src.Format == "asn" {
		asn, err := normalizeASN(src.URL)
		if err != nil {
			return err
		}
		src.URL = asn
		if src.Behavior == "domain" {
			return fmt.Errorf("ASN требует behavior ipcidr или classical")
		}
		if len(src.Headers) > 0 {
			return fmt.Errorf("заголовки доступны только HTTP(S)-источникам")
		}
	} else if strings.HasPrefix(src.URL, "ruleset:") {
		if _, err := rulesetSourceID(src.URL); err != nil {
			return err
		}
		if len(src.Headers) > 0 {
			return fmt.Errorf("заголовки доступны только HTTP(S)-источникам")
		}
	} else {
		if err := fetcher.ValidateURL(src.URL); err != nil {
			return err
		}
		if strings.HasPrefix(src.URL, "s3:") && len(src.Headers) > 0 {
			return fmt.Errorf("заголовки доступны только HTTP(S)-источникам")
		}
	}
	if err := fetcher.ValidateHeaders(src.Headers); err != nil {
		return err
	}
	if len(src.Headers) > 0 {
		canonical := make(map[string]string, len(src.Headers))
		for name, value := range src.Headers {
			canonical[http.CanonicalHeaderKey(name)] = value
		}
		src.Headers = canonical
	}
	if len(src.Selector) > 4096 {
		return fmt.Errorf("слишком длинный selector источника")
	}
	if (src.Format == "geosite" || src.Format == "geoip") && strings.TrimSpace(src.Selector) == "" {
		return fmt.Errorf("для geosite/geoip укажите selector: категории/страны через запятую или *")
	}
	for _, pattern := range []string{src.IncludeRegex, src.ExcludeRegex} {
		if len(pattern) > 4096 {
			return fmt.Errorf("регулярное выражение источника длиннее 4096 байт")
		}
		if _, err := regexp.Compile(pattern); err != nil {
			return fmt.Errorf("некорректное регулярное выражение источника")
		}
	}
	src.HeaderNames = nil
	src.ClearHeaders = false
	return nil
}

// RedactRuleset creates a detached DTO: callers can safely use it for all API
// responses and configuration exports without mutating the stored secrets.
func RedactRuleset(r model.Ruleset) model.Ruleset {
	r.Sources = append([]model.Source{}, r.Sources...)
	for i := range r.Sources {
		src := &r.Sources[i]
		src.HeaderNames = make([]string, 0, len(src.Headers))
		for name := range src.Headers {
			src.HeaderNames = append(src.HeaderNames, name)
		}
		slices.Sort(src.HeaderNames)
		src.Headers = nil
		src.ClearHeaders = false
	}
	return r
}

// An omitted headers object preserves credentials only for the same source ID.
// The URL fallback migrates old configurations that predate source IDs.
func preserveSourceHeaders(next *model.Ruleset, old model.Ruleset) {
	for i := range next.Sources {
		src := &next.Sources[i]
		src.Status = nil
		// Declarative files intentionally omit server-assigned IDs. Prefer the
		// existing position, otherwise adopt a unique URL/name match.
		if src.ID == "" {
			name := strings.TrimSpace(src.Name)
			if name == "" {
				name = fmt.Sprintf("Источник %d", i+1)
			}
			same := func(prior model.Source) bool { return strings.TrimSpace(src.URL) == prior.URL && name == prior.Name }
			if i < len(old.Sources) && same(old.Sources[i]) {
				src.ID = old.Sources[i].ID
			} else {
				found, count := "", 0
				for _, prior := range old.Sources {
					if same(prior) {
						found, count = prior.ID, count+1
					}
				}
				if count == 1 {
					src.ID = found
				}
			}
		}
		for _, prior := range old.Sources {
			match := src.ID != "" && prior.ID == src.ID || src.ID == "" && prior.ID == "" && strings.TrimSpace(src.URL) == prior.URL && src.Name == prior.Name
			if !match {
				continue
			}
			// A URL change must never forward an old token to a different source.
			if strings.TrimSpace(src.URL) == prior.URL {
				src.Status = prior.Status
				if src.Headers == nil && !src.ClearHeaders && len(prior.Headers) > 0 {
					src.Headers = make(map[string]string, len(prior.Headers))
					for k, v := range prior.Headers {
						src.Headers[k] = v
					}
				}
			}
			break
		}
		if src.ClearHeaders {
			src.Headers = nil
		}
		src.HeaderNames = nil
		src.ClearHeaders = false
	}
}

func rulesetSourceID(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "ruleset" || !slug.MatchString(u.Host) || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return "", fmt.Errorf("внутренний источник: ожидается ruleset://id")
	}
	return u.Host, nil
}

// Check every dependency, including disabled sources, so a later enable cannot
// turn an accepted graph into a cycle or silently reference a removed ruleset.
func validateDependencies(sets []model.Ruleset) error {
	byID := make(map[string]model.Ruleset, len(sets))
	for _, r := range sets {
		if _, ok := byID[r.ID]; ok {
			return fmt.Errorf("повторяющийся ID набора: %s", r.ID)
		}
		byID[r.ID] = r
	}
	state := map[string]uint8{}
	var visit func(string) error
	visit = func(id string) error {
		if state[id] == 1 {
			return fmt.Errorf("цикл зависимостей ruleset:// у набора %s", id)
		}
		if state[id] == 2 {
			return nil
		}
		state[id] = 1
		for _, src := range byID[id].Sources {
			if !strings.HasPrefix(src.URL, "ruleset:") {
				continue
			}
			dep, err := rulesetSourceID(src.URL)
			if err != nil {
				return err
			}
			if _, ok := byID[dep]; !ok {
				return fmt.Errorf("набор %s ссылается на отсутствующий ruleset://%s", id, dep)
			}
			if err := visit(dep); err != nil {
				return err
			}
		}
		state[id] = 2
		return nil
	}
	for _, r := range sets {
		if err := visit(r.ID); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) sourceWithStatus(ctx context.Context, src model.Source) (lines []string, status model.SourceStatus, err error) {
	lines, status, _, err = s.loadSource(ctx, src)
	return
}

type sourceMetadata struct {
	sizeBytes int
	format    string
}

func (s *Service) loadSource(ctx context.Context, src model.Source) (lines []string, status model.SourceStatus, metadata sourceMetadata, err error) {
	stage := "загрузки"
	status.CheckedAt = time.Now().UTC()
	if src.Status != nil {
		status.FetchedAt = src.Status.FetchedAt
	}
	defer func() {
		if err != nil {
			message := err.Error()
			if len(src.Headers) > 0 {
				// An authenticated upstream can reflect parts of a token, encoded
				// credentials, or cookies into its payload/errors. Never propagate
				// content-bearing errors from such sources to logs or the API.
				message = fmt.Sprintf("ошибка %s источника с секретными заголовками", stage)
				if status.HTTPStatus != 0 {
					message += fmt.Sprintf(" (HTTP %d)", status.HTTPStatus)
				}
			}
			err = fmt.Errorf("%s", message)
			status.Error = message
		} else {
			status.RuleCount = len(lines)
		}
	}()
	if err = ctx.Err(); err != nil {
		return
	}
	if src.Format == "asn" {
		var result fetcher.Result
		result, err = s.fetch.GetWithHeaders(ctx, asnSourceURL(src.URL), nil)
		status.HTTPStatus = result.HTTPStatus
		if err != nil {
			return
		}
		status.FetchedAt = result.FetchedAt
		lines, err = parseASNResponse(result.Body, src.URL)
		if err == nil {
			lines, err = rules.Transform(lines, "ipcidr", src.Behavior)
		}
	} else if strings.HasPrefix(src.URL, "ruleset:") {
		var id string
		id, err = rulesetSourceID(src.URL)
		if err != nil {
			return
		}
		dependency, ok := s.Store.Get(id)
		if !ok || dependency.LastBuild == nil {
			err = fmt.Errorf("ruleset://%s ещё не опубликован", id)
			return
		}
		lines, err = s.generationRules(id, dependency.LastBuild)
		if err != nil {
			return
		}
		behavior := dependency.LastBuild.Behavior
		if behavior == "" {
			behavior = dependency.Behavior
		}
		lines, err = rules.Transform(lines, behavior, src.Behavior)
		status.FetchedAt = time.Now().UTC()
	} else {
		if err = fetcher.ValidateURL(src.URL); err != nil {
			return
		}
		var u *url.URL
		u, err = url.Parse(src.URL)
		if err != nil || u == nil {
			err = fmt.Errorf("некорректный адрес источника")
			return
		}
		var data []byte
		if u.Scheme == "s3" {
			if s.S3 == nil || u.Host != s.Config.S3.Bucket {
				err = fmt.Errorf("S3 источник должен использовать настроенный bucket")
				return
			}
			data, err = s.S3.Get(ctx, strings.TrimPrefix(u.Path, "/"))
			if err == nil {
				status.FetchedAt = time.Now().UTC()
			}
		} else {
			var result fetcher.Result
			result, err = s.fetch.GetWithHeaders(ctx, src.URL, src.Headers)
			data, status.HTTPStatus = result.Body, result.HTTPStatus
			if err == nil {
				status.FetchedAt = result.FetchedAt
			}
		}
		if err != nil {
			return
		}
		stage = "разбора правил"
		metadata.sizeBytes = len(data)
		metadata.format = sourceFormat(data, src.Format)
		lines, err = rules.ParseSource(data, src.Format, src.Behavior, src.Selector)
	}
	if err != nil {
		return
	}
	stage = "фильтрации"
	lines, err = filterSourceRules(lines, src.IncludeRegex, src.ExcludeRegex)
	return
}

func filterSourceRules(lines []string, include, exclude string) ([]string, error) {
	var in, out *regexp.Regexp
	var err error
	if include != "" {
		in, err = regexp.Compile(include)
		if err != nil {
			return nil, fmt.Errorf("некорректный фильтр включения источника")
		}
	}
	if exclude != "" {
		out, err = regexp.Compile(exclude)
		if err != nil {
			return nil, fmt.Errorf("некорректный фильтр исключения источника")
		}
	}
	filtered := make([]string, 0, len(lines))
	for _, line := range lines {
		if (in == nil || in.MatchString(line)) && (out == nil || !out.MatchString(line)) {
			filtered = append(filtered, line)
		}
	}
	return filtered, nil
}

func normalizeASN(raw string) (string, error) {
	raw = strings.ToUpper(strings.TrimSpace(raw))
	if !strings.HasPrefix(raw, "AS") {
		return "", fmt.Errorf("ASN: ожидается AS13335")
	}
	number, err := strconv.ParseUint(strings.TrimPrefix(raw, "AS"), 10, 32)
	if err != nil || number == 0 {
		return "", fmt.Errorf("ASN: ожидается AS и число от 1 до 4294967295")
	}
	return "AS" + strconv.FormatUint(number, 10), nil
}

// RIPE RIS returns the latest routing-table snapshot (00/08/16 UTC). Request
// originating prefixes only: transit prefixes do not belong to the given ASN.
// https://stat.ripe.net/docs/data-api/api-endpoints/ris-prefixes
func asnSourceURL(asn string) string {
	q := url.Values{"resource": {asn}, "list_prefixes": {"true"}, "types": {"o"}, "af": {"v4,v6"}, "noise": {"keep"}}
	return "https://stat.ripe.net/data/ris-prefixes/data.json?" + q.Encode()
}

func parseASNResponse(data []byte, asn string) ([]string, error) {
	var response struct {
		Status     string `json:"status"`
		StatusCode int    `json:"status_code"`
		Data       struct {
			Resource     string `json:"resource"`
			ListPrefixes bool   `json:"list_prefixes"`
			Counts       map[string]struct {
				Originating *int `json:"originating"`
			} `json:"counts"`
			Prefixes map[string]struct {
				Originating []string `json:"originating"`
			} `json:"prefixes"`
		} `json:"data"`
	}
	if len(data) > fetcher.MaxBytes || json.Unmarshal(data, &response) != nil || response.Status != "ok" || response.StatusCode != 200 || !response.Data.ListPrefixes {
		return nil, fmt.Errorf("RIPEstat вернул некорректный ответ ASN")
	}
	resource, err := normalizeASN("AS" + strings.TrimPrefix(strings.ToUpper(response.Data.Resource), "AS"))
	if err != nil || resource != asn {
		return nil, fmt.Errorf("RIPEstat вернул другой ASN")
	}
	var result []string
	for _, family := range []string{"v4", "v6"} {
		count, ok := response.Data.Counts[family]
		prefixes, present := response.Data.Prefixes[family]
		if !ok || !present || count.Originating == nil || *count.Originating != len(prefixes.Originating) {
			return nil, fmt.Errorf("RIPEstat вернул обрезанный список префиксов ASN")
		}
		for _, raw := range prefixes.Originating {
			prefix, err := netip.ParsePrefix(raw)
			if err != nil || prefix.Addr().Is4() != (family == "v4") {
				return nil, fmt.Errorf("RIPEstat вернул некорректный CIDR")
			}
			result = append(result, prefix.Masked().String())
			if len(result) > rules.MaxRules {
				return nil, fmt.Errorf("слишком много префиксов ASN")
			}
		}
	}
	return rules.Normalize(result, "ipcidr")
}
