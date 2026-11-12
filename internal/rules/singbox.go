package rules

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"go4.org/netipx"
)

// Export version 2 needs sing-box >=1.10. All emitted items are available in
// that version. Unsupported Mihomo-only fields/flags fail instead of vanishing.
type singDocument struct {
	Version int        `json:"version"`
	Rules   []singRule `json:"rules"`
}
type stringList []string

func (s *stringList) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] == '"' {
		var v string
		if err := json.Unmarshal(b, &v); err != nil {
			return err
		}
		*s = []string{v}
		return nil
	}
	type plain []string
	return json.Unmarshal(b, (*plain)(s))
}

type portList []uint16

func (s *portList) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] != '[' {
		var v uint16
		if err := json.Unmarshal(b, &v); err != nil {
			return err
		}
		*s = []uint16{v}
		return nil
	}
	type plain []uint16
	return json.Unmarshal(b, (*plain)(s))
}

type singRule struct {
	Type            string     `json:"type,omitempty"`
	Mode            string     `json:"mode,omitempty"`
	Rules           []singRule `json:"rules,omitempty"`
	Invert          bool       `json:"invert,omitempty"`
	Domain          stringList `json:"domain,omitempty"`
	DomainSuffix    stringList `json:"domain_suffix,omitempty"`
	DomainKeyword   stringList `json:"domain_keyword,omitempty"`
	DomainRegex     stringList `json:"domain_regex,omitempty"`
	IPCIDR          stringList `json:"ip_cidr,omitempty"`
	SourceIPCIDR    stringList `json:"source_ip_cidr,omitempty"`
	Network         stringList `json:"network,omitempty"`
	Port            portList   `json:"port,omitempty"`
	PortRange       stringList `json:"port_range,omitempty"`
	SourcePort      portList   `json:"source_port,omitempty"`
	SourcePortRange stringList `json:"source_port_range,omitempty"`
	ProcessName     stringList `json:"process_name,omitempty"`
	ProcessPath     stringList `json:"process_path,omitempty"`
}

func parseSingBox(data []byte, behavior string) ([]string, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("sing-box JSON должен иметь кодировку UTF-8")
	}
	if err := checkJSONKeys(json.NewDecoder(bytes.NewReader(data)), 0); err != nil {
		return nil, fmt.Errorf("sing-box JSON: %w", err)
	}
	var document singDocument
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&document); err != nil {
		return nil, fmt.Errorf("sing-box JSON: %w", err)
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return nil, errors.New("лишние данные после sing-box JSON")
	}
	if document.Version < 1 || document.Version > 5 || document.Rules == nil {
		return nil, errors.New("sing-box: требуются version 1–5 и массив rules")
	}
	var lines []string
	for i, r := range document.Rules {
		if behavior == "domain" && r.domainOnly() {
			for _, v := range r.Domain {
				if _, err := normalizeClassical("DOMAIN,"+v, 0); err != nil {
					return nil, err
				}
				lines = append(lines, v)
			}
			for _, v := range r.DomainSuffix {
				if v == "" || strings.ContainsAny(v, "*+") {
					return nil, errors.New("некорректный domain_suffix")
				}
				if !strings.HasPrefix(v, ".") {
					v = "+." + v
				}
				lines = append(lines, v)
			}
			continue
		}
		part, err := singToClassical(r, 0)
		if err != nil {
			return nil, fmt.Errorf("sing-box rules[%d]: %w", i, err)
		}
		part, err = Transform(part, "classical", behavior)
		if err != nil {
			return nil, fmt.Errorf("sing-box rules[%d]: %w", i, err)
		}
		lines = append(lines, part...)
		if len(lines) > MaxRules {
			return nil, errors.New("sing-box превышает 1 000 000 правил")
		}
	}
	return Normalize(lines, behavior)
}

func (r singRule) domainOnly() bool {
	return (r.Type == "" || r.Type == "default") && !r.Invert && r.Mode == "" && len(r.Rules) == 0 &&
		len(r.Domain)+len(r.DomainSuffix) > 0 && len(r.DomainKeyword)+len(r.DomainRegex)+len(r.IPCIDR)+len(r.SourceIPCIDR)+len(r.Network)+len(r.Port)+len(r.PortRange)+len(r.SourcePort)+len(r.SourcePortRange)+len(r.ProcessName)+len(r.ProcessPath) == 0
}

func checkJSONKeys(d *json.Decoder, depth int) error {
	if depth > 32 {
		return errors.New("вложенность JSON превышает 32")
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			s, ok := key.(string)
			if !ok {
				return errors.New("неверный ключ JSON")
			}
			if seen[s] {
				return fmt.Errorf("повторный ключ %q", s)
			}
			seen[s] = true
			if err := checkJSONKeys(d, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for d.More() {
			if err := checkJSONKeys(d, depth+1); err != nil {
				return err
			}
		}
	default:
		return errors.New("неожиданный разделитель JSON")
	}
	_, err = d.Token()
	return err
}

func joinLogic(tp string, lines []string) (string, error) {
	if len(lines) == 0 {
		return "", errors.New("логическое правило не содержит условий")
	}
	if len(lines) == 1 && tp != "NOT" {
		return lines[0], nil
	}
	length := len(tp) + 3
	for _, line := range lines {
		length += len(line) + 3
	}
	if length > maxRuleBytes {
		return "", errors.New("составное правило превышает 16 KiB; разделите условия")
	}
	return tp + ",((" + strings.Join(lines, "),(") + "))", nil
}

func singToClassical(r singRule, depth int) ([]string, error) {
	if depth > 24 {
		return nil, errors.New("слишком глубокая вложенность sing-box")
	}
	var groups [][]string
	address := []string{}
	for _, v := range r.Domain {
		address = append(address, "DOMAIN,"+v)
	}
	for _, v := range r.DomainSuffix {
		if strings.HasPrefix(v, ".") {
			address = append(address, "DOMAIN-REGEX,"+domainPatternRegex(v))
		} else {
			address = append(address, "DOMAIN-SUFFIX,"+v)
		}
	}
	for _, v := range r.DomainKeyword {
		address = append(address, "DOMAIN-KEYWORD,"+v)
	}
	for _, v := range r.DomainRegex {
		if _, err := regexp.Compile(v); err != nil {
			return nil, fmt.Errorf("domain_regex: %w", err)
		}
		// Mihomo applies IgnoreCase by default; sing-box uses RE2's explicit
		// flags. Disable the implicit flag, preserving any flags in v itself.
		address = append(address, "DOMAIN-REGEX,(?-i)"+v)
	}
	for _, v := range r.IPCIDR {
		n, err := Normalize([]string{v}, "ipcidr")
		if err != nil {
			return nil, err
		}
		if len(n) != 1 {
			return nil, errors.New("пустой ip_cidr")
		}
		address = append(address, "IP-CIDR,"+n[0])
	}
	if len(address) > 0 {
		groups = append(groups, address)
	}
	for _, field := range []struct {
		values []string
		typ    string
	}{
		{r.SourceIPCIDR, "SRC-IP-CIDR"}, {r.Network, "NETWORK"}, {r.ProcessName, "PROCESS-NAME"}, {r.ProcessPath, "PROCESS-PATH"},
	} {
		var group []string
		for _, v := range field.values {
			if field.typ == "NETWORK" {
				v = strings.ToUpper(v)
			}
			if field.typ == "SRC-IP-CIDR" {
				n, err := Normalize([]string{v}, "ipcidr")
				if err != nil {
					return nil, err
				}
				if len(n) != 1 {
					return nil, errors.New("пустой source_ip_cidr")
				}
				v = n[0]
			}
			group = append(group, field.typ+","+v)
		}
		if len(group) > 0 {
			groups = append(groups, group)
		}
	}
	for _, field := range []struct {
		ports  []uint16
		ranges []string
		typ    string
	}{
		{r.Port, r.PortRange, "DST-PORT"}, {r.SourcePort, r.SourcePortRange, "SRC-PORT"},
	} {
		var group []string
		for _, v := range field.ports {
			group = append(group, field.typ+","+strconv.Itoa(int(v)))
		}
		for _, v := range field.ranges {
			bounds := strings.Split(v, ":")
			if len(bounds) != 2 {
				return nil, errors.New("неверный диапазон портов")
			}
			if bounds[0] == "" {
				bounds[0] = "0"
			}
			if bounds[1] == "" {
				bounds[1] = "65535"
			}
			a, e1 := strconv.ParseUint(bounds[0], 10, 16)
			b, e2 := strconv.ParseUint(bounds[1], 10, 16)
			if e1 != nil || e2 != nil || a > b {
				return nil, errors.New("неверный диапазон портов")
			}
			group = append(group, field.typ+","+bounds[0]+"-"+bounds[1])
		}
		if len(group) > 0 {
			groups = append(groups, group)
		}
	}
	if r.Type == "logical" {
		if len(groups) > 0 || (r.Mode != "and" && r.Mode != "or") || len(r.Rules) == 0 {
			return nil, errors.New("logical требует mode and/or и rules без обычных полей")
		}
		var children []string
		for _, child := range r.Rules {
			lines, err := singToClassical(child, depth+1)
			if err != nil {
				return nil, err
			}
			line, err := joinLogic("OR", lines)
			if err != nil {
				return nil, err
			}
			children = append(children, line)
		}
		line, err := joinLogic(strings.ToUpper(r.Mode), children)
		if err != nil {
			return nil, err
		}
		if r.Invert {
			line, err = joinLogic("NOT", []string{line})
		}
		return []string{line}, err
	}
	if (r.Type != "" && r.Type != "default") || r.Mode != "" || len(r.Rules) > 0 || len(groups) == 0 {
		return nil, errors.New("неизвестный тип или пустое правило sing-box")
	}
	if len(groups) == 1 && !r.Invert {
		return groups[0], nil
	}
	var conditions []string
	for _, group := range groups {
		line, err := joinLogic("OR", group)
		if err != nil {
			return nil, err
		}
		conditions = append(conditions, line)
	}
	line, err := joinLogic("AND", conditions)
	if err != nil {
		return nil, err
	}
	if r.Invert {
		line, err = joinLogic("NOT", []string{line})
	}
	return []string{line}, err
}

func encodeSingBox(lines []string, format, behavior string) ([]byte, error) {
	doc := singDocument{Version: 2, Rules: []singRule{}}
	if len(lines) > 0 && behavior != "classical" {
		r := singRule{}
		if behavior == "ipcidr" {
			r.IPCIDR = lines
		} else {
			for _, line := range lines {
				switch {
				case strings.Contains(line, "*"):
					r.DomainRegex = append(r.DomainRegex, domainPatternRegex(line))
				case strings.HasPrefix(line, "+."):
					r.DomainSuffix = append(r.DomainSuffix, line[2:])
				case strings.HasPrefix(line, "."):
					r.DomainSuffix = append(r.DomainSuffix, line)
				default:
					r.Domain = append(r.Domain, line)
				}
			}
		}
		doc.Rules = append(doc.Rules, r)
	} else {
		for _, line := range lines {
			r, err := classicalToSing(line, 0)
			if err != nil {
				return nil, err
			}
			doc.Rules = append(doc.Rules, r)
		}
	}
	if format == "srs" {
		return encodeSRS(doc)
	}
	return json.MarshalIndent(doc, "", "  ")
}

func classicalToSing(line string, depth int) (singRule, error) {
	r := singRule{}
	if depth > 32 {
		return r, errors.New("слишком глубокая вложенность")
	}
	tp, payload, params := splitClassical(line)
	if len(params) > 0 {
		return r, fmt.Errorf("sing-box: флаги %s нельзя перенести без потери смысла", strings.Join(params, ","))
	}
	switch tp {
	case "DOMAIN":
		r.Domain = []string{payload}
	case "DOMAIN-SUFFIX":
		r.DomainSuffix = []string{payload}
	case "DOMAIN-KEYWORD":
		r.DomainKeyword = []string{payload}
	case "DOMAIN-REGEX":
		if _, err := regexp.Compile(payload); err != nil {
			return r, fmt.Errorf("sing-box требует RE2-совместимое выражение: %w", err)
		}
		r.DomainRegex = []string{"(?i)" + payload}
	case "DOMAIN-WILDCARD":
		return r, errors.New("DOMAIN-WILDCARD нельзя автоматически перенести в sing-box; используйте DOMAIN-REGEX")
	case "IP-CIDR", "IP-CIDR6":
		r.IPCIDR = []string{payload}
	case "SRC-IP-CIDR":
		r.SourceIPCIDR = []string{payload}
	case "NETWORK":
		r.Network = []string{strings.ToLower(payload)}
	case "PROCESS-NAME":
		r.ProcessName = []string{payload}
	case "PROCESS-PATH":
		r.ProcessPath = []string{payload}
	case "DST-PORT", "SRC-PORT":
		var ports portList
		var ranges stringList
		for _, value := range strings.Split(payload, "/") {
			value = strings.Trim(value, "[] ")
			if strings.Contains(value, "-") {
				bounds := strings.Split(value, "-")
				a, _ := strconv.Atoi(bounds[0])
				b, _ := strconv.Atoi(bounds[1])
				if a > b {
					return r, errors.New("обратный диапазон портов")
				}
				ranges = append(ranges, strings.ReplaceAll(value, "-", ":"))
			} else {
				n, _ := strconv.ParseUint(value, 10, 16)
				ports = append(ports, uint16(n))
			}
		}
		if tp == "DST-PORT" {
			r.Port, r.PortRange = ports, ranges
		} else {
			r.SourcePort, r.SourcePortRange = ports, ranges
		}
	case "AND", "OR", "NOT":
		r.Type, r.Mode = "logical", strings.ToLower(tp)
		if tp == "NOT" {
			r.Mode, r.Invert = "and", true
		}
		inner := strings.TrimSpace(payload[1 : len(payload)-1])
		for len(inner) > 0 {
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
				return r, errors.New("некорректное logical правило")
			}
			child, err := classicalToSing(inner[1:end], depth+1)
			if err != nil {
				return r, err
			}
			r.Rules = append(r.Rules, child)
			inner = strings.TrimSpace(inner[end+1:])
			if strings.HasPrefix(inner, ",") {
				inner = strings.TrimSpace(inner[1:])
			} else if strings.HasPrefix(inner, "&&") || strings.HasPrefix(inner, "||") {
				inner = strings.TrimSpace(inner[2:])
			}
		}
	default:
		return r, fmt.Errorf("sing-box: %s не имеет поддерживаемого эквивалента; выберите YAML/text", tp)
	}
	return r, nil
}

// SRS wire implementation: magic/version + zlib; varint rule counts; default
// items, LOUDS domain matcher and versioned IP ranges. It does not link to the
// proxy engine. The optional official CLI test independently verifies output.
func encodeSRS(doc singDocument) ([]byte, error) {
	var body bytes.Buffer
	putUvarint(&body, uint64(len(doc.Rules)))
	for _, rule := range doc.Rules {
		if err := writeSRSRule(&body, rule); err != nil {
			return nil, err
		}
		if body.Len() > MaxInputBytes {
			return nil, errors.New("данные SRS превышают 64 MiB")
		}
	}
	var output bytes.Buffer
	output.Write([]byte{'S', 'R', 'S', 2})
	z, err := zlib.NewWriterLevel(&output, zlib.BestCompression)
	if err != nil {
		return nil, err
	}
	if _, err = z.Write(body.Bytes()); err != nil {
		return nil, err
	}
	if err = z.Close(); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}
func putUvarint(w *bytes.Buffer, value uint64) {
	var b [10]byte
	n := binary.PutUvarint(b[:], value)
	w.Write(b[:n])
}
func putSRSStrings(w *bytes.Buffer, tag byte, values []string) {
	if len(values) == 0 {
		return
	}
	w.WriteByte(tag)
	putUvarint(w, uint64(len(values)))
	for _, v := range values {
		putUvarint(w, uint64(len(v)))
		w.WriteString(v)
	}
}
func putSRSPorts(w *bytes.Buffer, tag byte, values []uint16) {
	if len(values) == 0 {
		return
	}
	w.WriteByte(tag)
	putUvarint(w, uint64(len(values)))
	for _, v := range values {
		var b [2]byte
		binary.BigEndian.PutUint16(b[:], v)
		w.Write(b[:])
	}
}
func writeSRSRule(w *bytes.Buffer, r singRule) error {
	if r.Type == "logical" {
		w.WriteByte(1)
		if r.Mode == "and" {
			w.WriteByte(0)
		} else {
			w.WriteByte(1)
		}
		putUvarint(w, uint64(len(r.Rules)))
		for _, child := range r.Rules {
			if err := writeSRSRule(w, child); err != nil {
				return err
			}
		}
	} else {
		w.WriteByte(0)
		putSRSStrings(w, 1, r.Network)
		if len(r.Domain) > 0 || len(r.DomainSuffix) > 0 {
			w.WriteByte(2)
			if err := writeSRSDomains(w, r.Domain, r.DomainSuffix); err != nil {
				return err
			}
		}
		putSRSStrings(w, 3, r.DomainKeyword)
		putSRSStrings(w, 4, r.DomainRegex)
		for _, item := range []struct {
			tag    byte
			values []string
		}{{5, r.SourceIPCIDR}, {6, r.IPCIDR}} {
			if len(item.values) > 0 {
				w.WriteByte(item.tag)
				if err := writeSRSIPs(w, item.values); err != nil {
					return err
				}
			}
		}
		putSRSPorts(w, 7, r.SourcePort)
		putSRSStrings(w, 8, r.SourcePortRange)
		putSRSPorts(w, 9, r.Port)
		putSRSStrings(w, 10, r.PortRange)
		putSRSStrings(w, 11, r.ProcessName)
		putSRSStrings(w, 12, r.ProcessPath)
		w.WriteByte(255)
	}
	if r.Invert {
		w.WriteByte(1)
	} else {
		w.WriteByte(0)
	}
	return nil
}

func writeSRSDomains(w *bytes.Buffer, domains, suffixes []string) error {
	keys := append([]string(nil), domains...)
	for _, suffix := range suffixes {
		if strings.HasPrefix(suffix, ".") {
			keys = append(keys, "\r"+suffix)
		} else {
			keys = append(keys, "\n"+suffix)
		}
	}
	// The existing independently implemented LOUDS builder is reused with SRS
	// terminal markers. Convert only length framing from int64 to uvarint.
	var tree bytes.Buffer
	if err := encodeDomains(&tree, keys); err != nil {
		return err
	}
	r := wireReader{data: tree.Bytes()}
	w.WriteByte(0)
	for i := 0; i < 2; i++ {
		words, err := r.words((maxMRSNodes*2 + 63) / 64)
		if err != nil {
			return err
		}
		putUvarint(w, uint64(len(words)))
		for _, word := range words {
			var b [8]byte
			binary.BigEndian.PutUint64(b[:], word)
			w.Write(b[:])
		}
	}
	n, err := r.length(maxMRSNodes)
	if err != nil {
		return err
	}
	labels, err := r.take(n)
	if err != nil {
		return err
	}
	putUvarint(w, uint64(n))
	w.Write(labels)
	return nil
}
func writeSRSIPs(w *bytes.Buffer, values []string) error {
	var builder netipx.IPSetBuilder
	for _, v := range values {
		p, err := netip.ParsePrefix(v)
		if err != nil {
			return err
		}
		builder.AddPrefix(p)
	}
	set, err := builder.IPSet()
	if err != nil {
		return err
	}
	ranges := set.Ranges()
	w.WriteByte(1)
	writeInt(w, len(ranges))
	for _, r := range ranges {
		for _, addr := range []netip.Addr{r.From(), r.To()} {
			b := addr.AsSlice()
			putUvarint(w, uint64(len(b)))
			w.Write(b)
		}
	}
	return nil
}
