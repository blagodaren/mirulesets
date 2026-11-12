package service

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/dlclark/regexp2"
)

type Match struct {
	RulesetID        string   `json:"rulesetId"`
	Name             string   `json:"name"`
	Behavior         string   `json:"behavior"`
	Rules            []string `json:"rules"`
	MatchCount       int      `json:"matchCount"`
	UnsupportedRules int      `json:"unsupportedRules,omitempty"`
}

// Lookup checks published rules, without DNS/network resolution. Classical
// rules requiring connection metadata or external databases are reported as
// unknown, never silently treated as a definitive non-match.
func (s *Service) Lookup(query string) ([]Match, error) {
	query = strings.TrimSpace(query)
	if query == "" || len(query) > 253 {
		return nil, fmt.Errorf("введите домен или IPv4/IPv6 без URL и порта")
	}
	ip, parseErr := netip.ParseAddr(query)
	if parseErr == nil {
		if ip.Zone() != "" {
			return nil, fmt.Errorf("IPv6 zone в адресе не поддерживается")
		}
		ip = ip.Unmap()
	} else {
		query = strings.ToLower(strings.TrimSuffix(query, "."))
		for _, label := range strings.Split(query, ".") {
			if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
				return nil, fmt.Errorf("некорректный домен")
			}
			for _, c := range label {
				if !unicode.IsLetter(c) && !unicode.IsDigit(c) && c != '-' && c != '_' {
					return nil, fmt.Errorf("введите домен без URL, порта и маски")
				}
			}
		}
	}
	result := []Match{}
	deadline := time.Now().Add(10 * time.Second)
	for _, r := range s.Store.List() {
		if r.LastBuild == nil {
			continue
		}
		lines, err := s.generationRules(r.ID, r.LastBuild)
		if err != nil {
			return nil, fmt.Errorf("проверка набора %s: %w", r.ID, err)
		}
		behavior := r.LastBuild.Behavior
		if behavior == "" {
			behavior = r.Behavior
		}
		match := Match{RulesetID: r.ID, Name: r.Name, Behavior: behavior, Rules: []string{}}
		for _, line := range lines {
			if time.Now().After(deadline) {
				return nil, fmt.Errorf("проверка превысила 10 секунд; уменьшите число опубликованных правил")
			}
			matched, supported := lookupRule(line, behavior, query, ip)
			if !supported {
				match.UnsupportedRules++
			}
			if matched {
				match.MatchCount++
				if len(match.Rules) < 100 {
					match.Rules = append(match.Rules, line)
				}
			}
		}
		if match.MatchCount > 0 || match.UnsupportedRules > 0 {
			result = append(result, match)
		}
	}
	return result, nil
}

func lookupRule(line, behavior, domain string, ip netip.Addr) (matched, supported bool) {
	switch behavior {
	case "domain":
		return !ip.IsValid() && matchDomainPattern(line, domain), true
	case "ipcidr":
		prefix, err := netip.ParsePrefix(line)
		return err == nil && ip.IsValid() && prefix.Contains(ip), err == nil
	case "classical":
		typ, payload, _ := strings.Cut(line, ",")
		switch typ {
		case "DOMAIN":
			return !ip.IsValid() && payload == domain, true
		case "DOMAIN-SUFFIX":
			return !ip.IsValid() && (payload == domain || strings.HasSuffix(domain, "."+payload)), true
		case "DOMAIN-KEYWORD":
			return !ip.IsValid() && strings.Contains(domain, payload), true
		case "DOMAIN-WILDCARD":
			if ip.IsValid() {
				return false, true
			}
			var pattern strings.Builder
			pattern.WriteString("^")
			for _, c := range payload {
				switch c {
				case '*':
					pattern.WriteString(".*")
				case '?':
					pattern.WriteString(".")
				default:
					pattern.WriteString(regexp.QuoteMeta(string(c)))
				}
			}
			pattern.WriteString("$")
			re, err := regexp.Compile(pattern.String())
			return err == nil && re.MatchString(domain), err == nil
		case "DOMAIN-REGEX":
			if ip.IsValid() {
				return false, true
			}
			re, err := regexp2.Compile(payload, regexp2.IgnoreCase)
			if err != nil {
				return false, false
			}
			re.MatchTimeout = 20 * time.Millisecond
			matched, err := re.MatchString(domain)
			return matched && err == nil, err == nil
		case "IP-CIDR", "IP-CIDR6":
			fields := strings.Split(payload, ",")
			for _, flag := range fields[1:] {
				if flag != "no-resolve" {
					return false, false
				}
			}
			prefix, err := netip.ParsePrefix(fields[0])
			return err == nil && ip.IsValid() && prefix.Contains(ip), err == nil
		default:
			return false, false
		}
	}
	return false, false
}

// Domain-provider '*' consumes exactly one label; '+.' consumes zero or more
// labels and '.' consumes one or more. DOMAIN-WILDCARD has separate semantics.
func matchDomainPattern(pattern, domain string) bool {
	minimumExtra, allowExtra := 0, false
	if strings.HasPrefix(pattern, "+.") {
		pattern = pattern[2:]
		allowExtra = true
	} else if strings.HasPrefix(pattern, ".") {
		pattern = pattern[1:]
		allowExtra = true
		minimumExtra = 1
	}
	parts, labels := strings.Split(pattern, "."), strings.Split(domain, ".")
	extra := len(labels) - len(parts)
	if extra < minimumExtra || !allowExtra && extra != 0 {
		return false
	}
	for i, part := range parts {
		if part != "*" && part != labels[i+extra] {
			return false
		}
	}
	return true
}
