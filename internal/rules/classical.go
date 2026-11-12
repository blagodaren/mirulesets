package rules

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/dlclark/regexp2"
)

// Regex/logic payloads can themselves contain commas. Treating every comma as
// a field boundary would corrupt quantifiers and nested classical rules.
func splitClassical(line string) (tp, payload string, params []string) {
	tp, rest, found := strings.Cut(line, ",")
	tp = strings.ToUpper(strings.TrimSpace(tp))
	if !found {
		return tp, "", nil
	}
	if tp == "AND" || tp == "OR" || tp == "NOT" || strings.HasSuffix(tp, "-REGEX") {
		return tp, strings.TrimSpace(rest), nil
	}
	fields := strings.Split(rest, ",")
	payload = strings.TrimSpace(fields[0])
	for _, field := range fields[1:] {
		params = append(params, strings.TrimSpace(field))
	}
	return
}

func normalizeClassical(line string, depth int) (string, error) {
	if depth > 32 {
		return "", errors.New("вложенность логических правил превышает 32 уровня")
	}
	tp, payload, params := splitClassical(line)
	if payload == "" {
		return "", fmt.Errorf("правилу %s требуется значение", tp)
	}
	if tp == "MATCH" || tp == "SUB-RULE" || (tp == "RULE-SET" && depth == 0) {
		return "", fmt.Errorf("%s не поддерживается в classical rule-provider", tp)
	}
	canHaveParams := false
	var err error
	switch tp {
	case "AND", "OR", "NOT":
		err = validateLogic(payload, tp, depth+1)
	case "DOMAIN-REGEX", "PROCESS-NAME-REGEX", "PROCESS-PATH-REGEX":
		_, err = regexp2.Compile(payload, regexp2.IgnoreCase)
	case "DOMAIN", "DOMAIN-SUFFIX":
		payload, err = normalizeDomain(payload)
		if err == nil && (strings.ContainsAny(payload, "*+") || strings.HasPrefix(payload, ".")) {
			err = errors.New("для масок используйте DOMAIN-WILDCARD или DOMAIN-REGEX")
		}
	case "DOMAIN-KEYWORD", "DOMAIN-WILDCARD":
		payload = strings.ToLower(payload)
	case "IP-CIDR", "IP-CIDR6", "SRC-IP-CIDR", "IP-SUFFIX", "SRC-IP-SUFFIX":
		canHaveParams = true
		var prefix netip.Prefix
		prefix, err = netip.ParsePrefix(payload)
		if err == nil && !strings.Contains(tp, "SUFFIX") {
			payload = prefix.Masked().String()
		}
	case "IP-ASN", "SRC-IP-ASN":
		canHaveParams = true
		_, err = strconv.ParseUint(payload, 10, 32)
	case "GEOIP", "SRC-GEOIP":
		canHaveParams = true
	case "GEOSITE":
		// Availability of geosite/geoip names depends on the consuming client's
		// own geo database. Preserve the name; syntax checking cannot resolve it.
	case "SRC-PORT", "DST-PORT", "IN-PORT":
		err = validateRanges(payload, 65535, false)
	case "DSCP":
		err = validateRanges(payload, 63, true)
	case "UID":
		err = validateRanges(payload, 4294967295, false)
	case "NETWORK":
		payload = strings.ToUpper(payload)
		if payload != "TCP" && payload != "UDP" {
			err = errors.New("NETWORK поддерживает TCP или UDP")
		}
	case "IN-TYPE":
		payload = strings.ToUpper(payload)
		valid := "/HTTP/HTTPS/SOCKS/SOCKS4/SOCKS5/SHADOWSOCKS/SNELL/VMESS/VLESS/REDIR/TPROXY/TROJAN/TUNNEL/TUN/TUIC/HYSTERIA2/ANYTLS/MIERU/SUDOKU/TRUSTTUNNEL/SHADOWQUIC/INNER/"
		for _, typ := range strings.Split(payload, "/") {
			if typ == "" || !strings.Contains(valid, "/"+typ+"/") {
				err = fmt.Errorf("неизвестный тип входящего подключения %q", typ)
				break
			}
		}
	case "IN-USER", "IN-NAME", "REMATCH-NAME", "PROCESS-NAME", "PROCESS-PATH", "PROCESS-NAME-WILDCARD", "PROCESS-PATH-WILDCARD":
	case "RULE-SET":
		canHaveParams = true // Mihomo permits references inside logical rules.
	default:
		return "", fmt.Errorf("неподдерживаемый тип classical-правила %q", tp)
	}
	if err != nil {
		return "", fmt.Errorf("%s: %w", tp, err)
	}
	for _, param := range params {
		if !canHaveParams || (param != "no-resolve" && param != "src") {
			return "", fmt.Errorf("%s: неподдерживаемый флаг %q; в rule-provider не указывается прокси-группа", tp, param)
		}
	}
	output := tp + "," + payload
	if len(params) > 0 {
		output += "," + strings.Join(params, ",")
	}
	return output, nil
}

func validateRanges(payload string, maximum uint64, allowWildcard bool) error {
	if payload == "*" && allowWildcard {
		return nil
	}
	parts := strings.Split(payload, "/")
	if len(parts) > 28 {
		return errors.New("допускается не более 28 диапазонов")
	}
	for _, part := range parts {
		bounds := strings.Split(strings.Trim(part, "[] "), "-")
		if len(bounds) > 2 {
			return fmt.Errorf("некорректный числовой диапазон %q", part)
		}
		for _, bound := range bounds {
			number, err := strconv.ParseUint(strings.TrimSpace(bound), 10, 64)
			if err != nil || number > maximum {
				return fmt.Errorf("значение диапазона %q должно быть от 0 до %d", bound, maximum)
			}
		}
	}
	return nil
}

func validateLogic(payload, tp string, depth int) error {
	if len(payload) < 4 || payload[0] != '(' || payload[len(payload)-1] != ')' {
		return errors.New("логическое выражение должно иметь вид ((TYPE,value),(TYPE,value))")
	}
	inner := strings.TrimSpace(payload[1 : len(payload)-1])
	count := 0
	for len(inner) > 0 {
		if inner[0] != '(' {
			return errors.New("каждое вложенное правило должно быть заключено в скобки")
		}
		level, end := 0, -1
		for i, c := range inner {
			if c == '(' {
				level++
			}
			if c == ')' {
				level--
				if level == 0 {
					end = i
					break
				}
			}
		}
		if end < 0 {
			return errors.New("незакрытые скобки в логическом правиле")
		}
		if _, err := normalizeClassical(inner[1:end], depth); err != nil {
			return err
		}
		count++
		inner = strings.TrimSpace(inner[end+1:])
		if inner == "" {
			break
		}
		switch {
		case strings.HasPrefix(inner, ","):
			inner = strings.TrimSpace(inner[1:])
		case strings.HasPrefix(inner, "&&") || strings.HasPrefix(inner, "||"):
			inner = strings.TrimSpace(inner[2:])
		default:
			return errors.New("между вложенными правилами требуется разделитель")
		}
		if inner == "" {
			return errors.New("логическое выражение оканчивается разделителем")
		}
	}
	if count == 0 || (tp == "NOT" && count != 1) {
		return errors.New("NOT требует ровно одно вложенное правило; AND и OR — хотя бы одно")
	}
	return nil
}
