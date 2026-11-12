package rules

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"unicode/utf8"
)

// Hosts imports the names, not the destination address of a hosts mapping.
// Adblock deliberately accepts only DNS-domain filters: path/resource/cosmetic
// filters and allow-list exceptions cannot be represented by a positive set.
func parseDomainList(data []byte, format, behavior string) ([]string, error) {
	data = bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})
	if !utf8.Valid(data) || bytes.Count(data, []byte{'\n'}) > MaxRules*2 {
		return nil, errors.New("некорректная кодировка или слишком много строк списка")
	}
	var lines []string
	for i, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if len(line) > maxRuleBytes {
			return nil, fmt.Errorf("строка %d слишком длинная", i+1)
		}
		if format == "adblock" && strings.HasPrefix(line, "##") {
			return nil, fmt.Errorf("Adblock, строка %d: косметические фильтры не поддерживаются", i+1)
		}
		if line == "" || strings.HasPrefix(line, "#") || (format == "adblock" && strings.HasPrefix(line, "!")) {
			continue
		}
		if format == "hosts" {
			line, _, _ = strings.Cut(line, "#")
			fields := strings.Fields(line)
			if len(fields) < 2 {
				return nil, fmt.Errorf("hosts, строка %d: ожидается IP и имя домена", i+1)
			}
			if addr, err := netip.ParseAddr(fields[0]); err != nil || addr.Zone() != "" {
				return nil, fmt.Errorf("hosts, строка %d: некорректный IP", i+1)
			}
			for _, domain := range fields[1:] {
				if strings.ContainsAny(domain, "*+") || strings.HasPrefix(domain, ".") {
					return nil, fmt.Errorf("hosts, строка %d: маски недопустимы", i+1)
				}
				lines = append(lines, domain)
			}
		} else {
			if line == "[Adblock Plus 2.0]" || line == "[Adblock]" {
				continue
			}
			if strings.HasPrefix(line, "||") && strings.HasSuffix(line, "^") {
				domain := strings.TrimSuffix(strings.TrimPrefix(line, "||"), "^")
				if domain == "" || strings.ContainsAny(domain, "*^$|/#@") {
					return nil, fmt.Errorf("Adblock, строка %d: ожидается ||domain.example^ без опций", i+1)
				}
				lines = append(lines, "+."+domain)
			} else if !strings.ContainsAny(line, "|^$/*@#[]") {
				// Bare domain entries are the common DNS-filter extension.
				if strings.Contains(line, "+") || strings.HasPrefix(line, ".") {
					return nil, fmt.Errorf("Adblock, строка %d: ожидается точное имя домена", i+1)
				}
				lines = append(lines, line)
			} else {
				return nil, fmt.Errorf("Adblock, строка %d: URL, исключения @@, опции и косметические фильтры нельзя перенести без потери смысла; используйте DNS-список", i+1)
			}
		}
		if len(lines) > MaxRules {
			return nil, errors.New("список превышает 1 000 000 правил")
		}
	}
	return Transform(lines, "domain", behavior)
}

// The protobuf wire reader is intentionally allocation bounded. DAT is the
// v2ray GeoSiteList/GeoIPList schema; unknown protobuf fields remain skippable.
type protoField struct {
	number int
	wire   byte
	data   []byte
	value  uint64
}

func nextProto(data *[]byte) (protoField, error) {
	var field protoField
	tag, n := binary.Uvarint(*data)
	if n <= 0 || tag>>3 == 0 || tag>>3 > (1<<29)-1 {
		return field, errors.New("некорректный protobuf tag")
	}
	*data = (*data)[n:]
	field.number, field.wire = int(tag>>3), byte(tag&7)
	switch field.wire {
	case 0:
		field.value, n = binary.Uvarint(*data)
		if n <= 0 {
			return field, io.ErrUnexpectedEOF
		}
		*data = (*data)[n:]
	case 1, 5:
		n = 8
		if field.wire == 5 {
			n = 4
		}
		if len(*data) < n {
			return field, io.ErrUnexpectedEOF
		}
		field.data, *data = (*data)[:n], (*data)[n:]
	case 2:
		size, read := binary.Uvarint(*data)
		if read <= 0 || size > uint64(len(*data)-read) {
			return field, io.ErrUnexpectedEOF
		}
		*data = (*data)[read:]
		field.data, *data = (*data)[:int(size)], (*data)[int(size):]
	default:
		return field, errors.New("неподдерживаемый protobuf wire type")
	}
	return field, nil
}

func parseGeoData(data []byte, format, behavior, selector string) ([]string, error) {
	selected := map[string]bool{}
	for _, code := range strings.Split(selector, ",") {
		code = strings.ToLower(strings.TrimSpace(code))
		if code == "" {
			return nil, errors.New("для DAT укажите selector: код категории/страны, коды через запятую или *")
		}
		if len(code) > 160 {
			return nil, errors.New("слишком длинный selector DAT")
		}
		selected[code] = false
	}
	_, all := selected["*"]
	if all && len(selected) != 1 {
		return nil, errors.New("selector * нельзя объединять с отдельными кодами")
	}
	var lines []string
	entries := 0
	for len(data) > 0 {
		field, err := nextProto(&data)
		if err != nil {
			return nil, fmt.Errorf("%s.dat: %w", format, err)
		}
		if field.number != 1 {
			continue
		}
		if field.wire != 2 {
			return nil, errors.New("DAT entry должен быть protobuf message")
		}
		entry := field.data
		code := ""
		inverse := false
		for len(entry) > 0 {
			f, err := nextProto(&entry)
			if err != nil {
				return nil, err
			}
			if f.number == 1 {
				if f.wire != 2 || !utf8.Valid(f.data) {
					return nil, errors.New("некорректный код категории DAT")
				}
				code = strings.ToLower(string(f.data))
			}
			if format == "geoip" && f.number == 3 {
				if f.wire != 0 {
					return nil, errors.New("некорректный inverse_match DAT")
				}
				inverse = f.value != 0
			}
		}
		if code == "" {
			return nil, errors.New("DAT entry без кода категории")
		}
		_, wanted := selected[code]
		if !all && !wanted {
			continue
		}
		if inverse {
			return nil, fmt.Errorf("geoip %s: inverse_match нельзя представить положительным набором CIDR", code)
		}
		selected[code] = true
		entries++
		entry = field.data
		for len(entry) > 0 {
			f, err := nextProto(&entry)
			if err != nil {
				return nil, err
			}
			if f.number != 2 {
				continue
			}
			if f.wire != 2 {
				return nil, errors.New("DAT rule должен быть protobuf message")
			}
			var line string
			if format == "geosite" {
				line, err = geoDomain(f.data)
			} else {
				line, err = geoPrefix(f.data)
			}
			if err != nil {
				return nil, fmt.Errorf("%s %s: %w", format, code, err)
			}
			lines = append(lines, line)
			if len(lines) > MaxRules {
				return nil, errors.New("DAT превышает 1 000 000 выбранных правил")
			}
		}
	}
	if entries == 0 {
		return nil, errors.New("в DAT не найдена выбранная категория")
	}
	if !all {
		for code, found := range selected {
			if !found {
				return nil, fmt.Errorf("в DAT отсутствует категория %s", code)
			}
		}
	}
	from := "classical"
	if format == "geoip" {
		from = "ipcidr"
	}
	return Transform(lines, from, behavior)
}

func geoDomain(data []byte) (string, error) {
	typ, value := uint64(0), ""
	for len(data) > 0 {
		f, err := nextProto(&data)
		if err != nil {
			return "", err
		}
		switch f.number {
		case 1:
			if f.wire != 0 {
				return "", errors.New("некорректный тип домена")
			}
			typ = f.value
		case 2:
			if f.wire != 2 || !utf8.Valid(f.data) {
				return "", errors.New("некорректный домен")
			}
			value = string(f.data)
		}
	}
	if value == "" || typ > 3 {
		return "", errors.New("неизвестный или пустой домен DAT")
	}
	return []string{"DOMAIN-KEYWORD,", "DOMAIN-REGEX,", "DOMAIN-SUFFIX,", "DOMAIN,"}[typ] + value, nil
}

func geoPrefix(data []byte) (string, error) {
	var ip []byte
	bits := uint64(0)
	for len(data) > 0 {
		f, err := nextProto(&data)
		if err != nil {
			return "", err
		}
		switch f.number {
		case 1:
			if f.wire != 2 {
				return "", errors.New("некорректный IP DAT")
			}
			ip = f.data
		case 2:
			if f.wire != 0 {
				return "", errors.New("некорректная маска DAT")
			}
			bits = f.value
		}
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok || bits > uint64(addr.BitLen()) {
		return "", errors.New("неверный IP или маска DAT")
	}
	return netip.PrefixFrom(addr, int(bits)).Masked().String(), nil
}
