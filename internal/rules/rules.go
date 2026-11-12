// Package rules reads and writes Mihomo rule-provider formats without running a
// proxy process. Normalization is strict: malformed rules never disappear silently.
package rules

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"
)

const (
	MaxInputBytes  = 64 << 20
	MaxRules       = 1_000_000
	maxRuleBytes   = 16 << 10
	maxDomainBytes = 1024
)

func validateBehavior(behavior string) error {
	switch behavior {
	case "domain", "ipcidr", "classical":
		return nil
	default:
		return fmt.Errorf("неподдерживаемый behavior %q; используйте domain, ipcidr или classical", behavior)
	}
}

func validateFormat(format, behavior string) error {
	if err := validateBehavior(behavior); err != nil {
		return err
	}
	switch format {
	case "yaml", "text", "singbox", "srs":
		return nil
	case "mrs":
		if behavior == "classical" {
			return errors.New("Mihomo MRS поддерживает только domain и ipcidr; classical нельзя сохранить в MRS")
		}
		return nil
	default:
		return fmt.Errorf("неподдерживаемый формат %q; используйте yaml, text, mrs, singbox или srs", format)
	}
}

// Parse accepts YAML payload (or rules), line-based text, and binary MRS v1.
func Parse(data []byte, format, behavior string) ([]string, error) {
	return ParseSource(data, format, behavior, "")
}

// ParseSource adds an explicit category selector for geosite.dat/geoip.dat.
func ParseSource(data []byte, format, behavior, selector string) ([]string, error) {
	if len(data) > MaxInputBytes {
		return nil, errors.New("рулсет превышает лимит входных данных 64 MiB")
	}
	if format == "auto" {
		format = detectFormat(data)
	}
	if err := validateBehavior(behavior); err != nil {
		return nil, err
	}
	switch format {
	case "geosite", "geoip":
		return parseGeoData(data, format, behavior, selector)
	case "hosts", "adblock":
		return parseDomainList(data, format, behavior)
	case "singbox":
		return parseSingBox(data, behavior)
	case "srs":
		return nil, errors.New("импорт SRS не поддерживается; декомпилируйте его официальным sing-box в JSON")
	}
	if err := validateFormat(format, behavior); err != nil {
		return nil, err
	}
	if len(data) > MaxInputBytes {
		return nil, errors.New("рулсет превышает лимит входных данных 64 MiB")
	}
	if format == "mrs" {
		return decodeMRS(data, behavior)
	}
	data = bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})
	if !utf8.Valid(data) {
		return nil, errors.New("текстовый рулсет должен иметь кодировку UTF-8")
	}
	var lines []string
	if format == "yaml" {
		var document yaml.Node
		decoder := yaml.NewDecoder(bytes.NewReader(data))
		if err := decoder.Decode(&document); err != nil {
			return nil, fmt.Errorf("некорректный YAML: %w", err)
		}
		if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
			return nil, errors.New("YAML должен содержать список payload или rules")
		}
		root := document.Content[0]
		var payload *yaml.Node
		for i := 0; i < len(root.Content); i += 2 {
			key, value := root.Content[i], root.Content[i+1]
			if key.Value != "payload" && key.Value != "rules" {
				continue
			}
			if payload != nil {
				return nil, errors.New("YAML должен содержать ровно один ключ payload или rules")
			}
			if value.Kind != yaml.SequenceNode {
				return nil, errors.New("YAML payload должен быть списком строк")
			}
			payload = value
		}
		if payload == nil {
			return nil, errors.New("YAML должен содержать список payload или rules")
		}
		if len(payload.Content) > MaxRules {
			return nil, errors.New("рулсет превышает лимит 1 000 000 правил")
		}
		lines = make([]string, 0, len(payload.Content))
		for _, node := range payload.Content {
			if node.Kind != yaml.ScalarNode || node.Tag != "!!str" {
				return nil, fmt.Errorf("YAML, строка %d: правило должно быть строкой; объекты, ссылки и числа недопустимы", node.Line)
			}
			lines = append(lines, node.Value)
		}
		var next yaml.Node
		if err := decoder.Decode(&next); err != io.EOF {
			return nil, errors.New("несколько YAML-документов в одном файле не поддерживаются")
		}
	} else {
		// Count before Split to avoid a large slice allocation from newline-only input.
		if bytes.Count(data, []byte{'\n'}) > MaxRules*2 {
			return nil, errors.New("текстовый рулсет содержит слишком много строк")
		}
		lines = strings.Split(string(data), "\n")
	}
	return Normalize(lines, behavior)
}

func detectFormat(data []byte) string {
	if len(data) >= 4 && bytes.Equal(data[:4], []byte{0x28, 0xb5, 0x2f, 0xfd}) {
		return "mrs"
	}
	data = bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})
	trimmed := bytes.TrimSpace(data)
	if bytes.HasPrefix(trimmed, []byte{'{'}) {
		var envelope struct {
			Version json.RawMessage `json:"version"`
			Rules   json.RawMessage `json:"rules"`
		}
		if json.Unmarshal(trimmed, &envelope) == nil && len(envelope.Version) > 0 && len(envelope.Rules) > 0 {
			return "singbox"
		}
		return "yaml"
	}
	for len(data) > 0 {
		line, rest, found := bytes.Cut(data, []byte{'\n'})
		line = bytes.TrimSpace(line)
		if bytes.HasPrefix(line, []byte("[Adblock")) || bytes.HasPrefix(line, []byte("||")) || bytes.HasPrefix(line, []byte("@@||")) {
			return "adblock"
		}
		if fields := bytes.Fields(line); len(fields) >= 2 {
			if _, err := netip.ParseAddr(string(fields[0])); err == nil {
				return "hosts"
			}
		}
		if bytes.HasPrefix(line, []byte("payload:")) || bytes.HasPrefix(line, []byte("rules:")) {
			return "yaml"
		}
		if !found {
			break
		}
		data = rest
	}
	return "text"
}

// Normalize validates each rule, canonicalizes domains/CIDRs, and deduplicates
// while preserving the first occurrence (and therefore classical rule order).
func Normalize(lines []string, behavior string) ([]string, error) {
	if err := validateBehavior(behavior); err != nil {
		return nil, err
	}
	if len(lines) > MaxRules*2 {
		return nil, errors.New("рулсет содержит слишком много строк")
	}
	seen := make(map[string]struct{}, len(lines))
	result := make([]string, 0, len(lines))
	totalBytes := 0
	for i, raw := range lines {
		totalBytes += len(raw)
		if totalBytes > MaxInputBytes {
			return nil, errors.New("рулсет превышает лимит входных данных 64 MiB")
		}
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		if !utf8.ValidString(line) || len(line) > maxRuleBytes || strings.ContainsAny(line, "\r\n\x00") {
			return nil, fmt.Errorf("строка %d: некорректное или слишком длинное правило", i+1)
		}
		var err error
		switch behavior {
		case "domain":
			line, err = normalizeDomain(line)
		case "ipcidr":
			var prefix netip.Prefix
			prefix, err = netip.ParsePrefix(line)
			if err != nil && !strings.Contains(line, "/") {
				var address netip.Addr
				address, err = netip.ParseAddr(line)
				if err == nil && address.Zone() != "" {
					err = errors.New("IPv6-адрес с зоной нельзя использовать в рулсете")
				}
				if err == nil {
					prefix = netip.PrefixFrom(address, address.BitLen())
				}
			}
			if err == nil {
				line = prefix.Masked().String()
			}
		case "classical":
			line, err = normalizeClassical(line, 0)
		}
		if err != nil {
			return nil, fmt.Errorf("строка %d: %w", i+1, err)
		}
		if _, exists := seen[line]; exists {
			continue
		}
		seen[line] = struct{}{}
		result = append(result, line)
		if len(result) > MaxRules {
			return nil, errors.New("рулсет превышает лимит 1 000 000 правил")
		}
	}
	return result, nil
}

func normalizeDomain(domain string) (string, error) {
	if len(domain) == 0 || len(domain) > maxDomainBytes || strings.ContainsAny(domain, ",/:\\\x00") || strings.HasSuffix(domain, ".") {
		return "", fmt.Errorf("некорректный шаблон домена %q", domain)
	}
	for _, r := range domain {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return "", fmt.Errorf("недопустимый пробельный символ в домене %q", domain)
		}
	}
	domain = strings.ToLower(domain)
	parts := strings.Split(domain, ".")
	for i, part := range parts {
		if part == "" && (i != 0 || len(parts) == 1) {
			return "", fmt.Errorf("пустая часть домена %q", domain)
		}
		if strings.Contains(part, "+") && (part != "+" || i != 0 || len(parts) == 1) {
			return "", fmt.Errorf("маска + должна занимать первую часть домена целиком: %q", domain)
		}
		if strings.Contains(part, "*") && part != "*" {
			return "", fmt.Errorf("маска * должна занимать целую часть домена: %q", domain)
		}
	}
	return domain, nil
}

// Encode writes a normalized ruleset. Empty text/YAML sets are valid; MRS has no
// portable empty-set representation and is rejected, as in Mihomo's converter.
func Encode(lines []string, format, behavior string) ([]byte, error) {
	if err := validateFormat(format, behavior); err != nil {
		return nil, err
	}
	normalized, err := Normalize(lines, behavior)
	if err != nil {
		return nil, err
	}
	switch format {
	case "singbox", "srs":
		return encodeSingBox(normalized, format, behavior)
	case "mrs":
		return encodeMRS(normalized, behavior)
	case "yaml":
		return yaml.Marshal(struct {
			Payload []string `yaml:"payload"`
		}{normalized})
	default:
		if len(normalized) == 0 {
			return []byte{}, nil
		}
		return []byte(strings.Join(normalized, "\n") + "\n"), nil
	}
}

// Transform converts behaviors only when every input rule can be represented
// without broadening matching. It never drops unsupported rules or flags.
func Transform(lines []string, fromBehavior, toBehavior string) ([]string, error) {
	if err := validateBehavior(toBehavior); err != nil {
		return nil, err
	}
	normalized, err := Normalize(lines, fromBehavior)
	if err != nil {
		return nil, err
	}
	if fromBehavior == toBehavior {
		return normalized, nil
	}
	output := make([]string, 0, len(normalized))
	for _, line := range normalized {
		var converted string
		switch {
		case fromBehavior == "domain" && toBehavior == "classical":
			switch {
			case strings.HasPrefix(line, "+.") && !strings.Contains(line[2:], "*"):
				converted = "DOMAIN-SUFFIX," + line[2:]
			case !strings.ContainsAny(line, "*+") && !strings.HasPrefix(line, "."):
				converted = "DOMAIN," + line
			default:
				converted = "DOMAIN-REGEX," + domainPatternRegex(line)
			}
		case fromBehavior == "ipcidr" && toBehavior == "classical":
			converted = "IP-CIDR," + line
		case fromBehavior == "classical":
			tp, payload, params := splitClassical(line)
			if len(params) > 0 {
				return nil, fmt.Errorf("правило %q нельзя преобразовать в %s без потери флагов", line, toBehavior)
			}
			if toBehavior == "domain" && (tp == "DOMAIN" || tp == "DOMAIN-SUFFIX") && !strings.ContainsAny(payload, "*+") && !strings.HasPrefix(payload, ".") {
				converted = payload
				if tp == "DOMAIN-SUFFIX" {
					converted = "+." + payload
				}
			} else if toBehavior == "ipcidr" && (tp == "IP-CIDR" || tp == "IP-CIDR6") {
				converted = payload
			}
		}
		if converted == "" {
			return nil, fmt.Errorf("правило %q нельзя представить как %s без изменения смысла", line, toBehavior)
		}
		output = append(output, converted)
	}
	return Normalize(output, toBehavior)
}

func domainPatternRegex(pattern string) string {
	prefix := "^"
	if strings.HasPrefix(pattern, "+.") {
		prefix += "(?:[^.]+\\.)*"
		pattern = pattern[2:]
	} else if strings.HasPrefix(pattern, ".") {
		prefix += "(?:[^.]+\\.)+"
		pattern = pattern[1:]
	}
	parts := strings.Split(pattern, ".")
	for i, part := range parts {
		if part == "*" {
			parts[i] = "[^.]+"
		} else {
			parts[i] = regexp.QuoteMeta(part)
		}
	}
	return prefix + strings.Join(parts, "\\.") + "$"
}
