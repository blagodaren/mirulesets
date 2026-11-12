package rules

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestDomainListImports(t *testing.T) {
	for _, tc := range []struct {
		format, input string
		want          []string
	}{
		{"hosts", "# names\n0.0.0.0 ADS.Example other.example # comment\n::1 ipv6.example\n", []string{"ads.example", "other.example", "ipv6.example"}},
		{"adblock", "[Adblock Plus 2.0]\n! comment\n||ads.example^\ntrack.example\n", []string{"+.ads.example", "track.example"}},
	} {
		t.Run(tc.format, func(t *testing.T) {
			for _, format := range []string{tc.format, "auto"} {
				got, err := Parse([]byte(tc.input), format, "domain")
				if err != nil {
					t.Fatal(err)
				}
				assertSameRules(t, got, tc.want)
			}
		})
	}
	for _, input := range []string{"@@||allowed.example^", "||example.com^$third-party", "example.com##.banner", "##.banner", "|https://example.com/path|", "||example.com/path^"} {
		if _, err := Parse([]byte(input), "adblock", "domain"); err == nil {
			t.Fatalf("accepted unsupported Adblock: %q", input)
		}
	}
	for _, input := range []string{"invalid example.com", "0.0.0.0 *.example.com", "127.0.0.1"} {
		if _, err := Parse([]byte(input), "hosts", "domain"); err == nil {
			t.Fatalf("accepted malformed hosts: %q", input)
		}
	}
}

func pbBytes(field int, data []byte) []byte {
	b := binary.AppendUvarint(nil, uint64(field<<3|2))
	b = binary.AppendUvarint(b, uint64(len(data)))
	return append(b, data...)
}
func pbUint(field int, n uint64) []byte {
	b := binary.AppendUvarint(nil, uint64(field<<3))
	return binary.AppendUvarint(b, n)
}
func geoFixture(code string, entries ...[]byte) []byte {
	body := pbBytes(1, []byte(code))
	for _, entry := range entries {
		body = append(body, pbBytes(2, entry)...)
	}
	return pbBytes(1, body)
}
func domainFixture(kind uint64, value string) []byte {
	return append(pbUint(1, kind), pbBytes(2, []byte(value))...)
}

func TestGeoDataImports(t *testing.T) {
	site := append(geoFixture("TEST", domainFixture(2, "example.com"), domainFixture(3, "exact.example")), geoFixture("OTHER", domainFixture(0, "keyword"), domainFixture(1, "^regexp\\.example$"))...)
	got, err := ParseSource(site, "geosite", "domain", "test")
	if err != nil {
		t.Fatal(err)
	}
	assertSameRules(t, got, []string{"+.example.com", "exact.example"})
	got, err = ParseSource(site, "geosite", "classical", "test,other")
	if err != nil || len(got) != 4 {
		t.Fatalf("all categories: %v %v", got, err)
	}
	if _, err = ParseSource(site, "geosite", "domain", "*"); err == nil {
		t.Fatal("keyword/regex silently lost")
	}
	for _, selector := range []string{"", "missing", "test,missing", "*,test"} {
		if _, err = ParseSource(site, "geosite", "classical", selector); err == nil {
			t.Fatalf("accepted invalid selector %q", selector)
		}
	}
	ip := append(pbBytes(1, []byte{192, 0, 2, 100}), pbUint(2, 24)...)
	geoip := geoFixture("ZZ", ip)
	got, err = ParseSource(geoip, "geoip", "ipcidr", "zz")
	if err != nil {
		t.Fatal(err)
	}
	assertSameRules(t, got, []string{"192.0.2.0/24"})
	inverse := append(pbBytes(1, []byte("ZZ")), pbBytes(2, ip)...)
	inverse = append(inverse, pbUint(3, 1)...)
	if _, err = ParseSource(pbBytes(1, inverse), "geoip", "ipcidr", "zz"); err == nil {
		t.Fatal("inverse geoip accepted")
	}
	for i := 0; i < len(geoip); i++ {
		if _, err = ParseSource(geoip[:i], "geoip", "ipcidr", "zz"); err == nil {
			t.Fatalf("truncated DAT accepted at %d", i)
		}
	}
}

func TestSingBoxJSON(t *testing.T) {
	if got, err := Parse([]byte(`{"payload":["version"]}`), "auto", "domain"); err != nil || len(got) != 1 || got[0] != "version" {
		t.Fatalf("JSON YAML auto detection regressed: %v %v", got, err)
	}
	if got, err := Parse([]byte(`{"version":2,"rules":[{"domain_suffix":[".sub.example","example.com"]}]}`), "singbox", "domain"); err != nil || !reflect.DeepEqual(got, []string{".sub.example", "+.example.com"}) {
		t.Fatalf("suffix semantics: %v %v", got, err)
	}
	for _, behavior := range []string{"domain", "ipcidr", "classical"} {
		t.Run(behavior, func(t *testing.T) {
			lines := map[string][]string{
				"domain": {"+.example.com", "exact.example"}, "ipcidr": {"192.0.2.0/24", "2001:db8::/32"}, "classical": {"DOMAIN,example.com", "IP-CIDR,192.0.2.0/24", "AND,((NETWORK,TCP),(DST-PORT,443))"},
			}[behavior]
			b, err := Encode(lines, "singbox", behavior)
			if err != nil {
				t.Fatal(err)
			}
			got, err := Parse(b, "auto", behavior)
			if err != nil {
				t.Fatal(err)
			}
			assertSameRules(t, got, lines)
		})
	}
	input := `{"version":2,"rules":[{"domain":["a.example","b.example"],"network":"tcp","port":[80,443]}]}`
	got, err := Parse([]byte(input), "singbox", "classical")
	if err != nil {
		t.Fatal(err)
	}
	want := "AND,((OR,((DOMAIN,a.example),(DOMAIN,b.example))),(NETWORK,TCP),(OR,((DST-PORT,80),(DST-PORT,443))))"
	if len(got) != 1 || got[0] != want {
		t.Fatalf("matching groups changed: %v", got)
	}
	for _, input := range []string{
		`{"version":2,"rules":[{"domain":"a.example","outbound":"proxy"}]}`,
		`{"version":2,"rules":[{"domain":"a.example","domain":"b.example"}]}`,
		`{"version":2,"rules":[{"ip_cidr":""}]}`,
		`{"version":2,"rules":[{"source_ip_cidr":""}]}`,
		`{"version":2,"rules":[{}]}`,
		`{"version":2,"rules":[{"type":"logical","mode":"and","rules":[]}]}`,
		`{"version":2,"rules":[{"domain":"a.example","port_range":"443:80"}]}`,
	} {
		if _, err := Parse([]byte(input), "singbox", "classical"); err == nil {
			t.Fatalf("accepted unsafe JSON: %s", input)
		}
	}
	for _, line := range []string{"IP-CIDR,192.0.2.0/24,no-resolve", "GEOSITE,google", "DOMAIN-REGEX,(?<=a)b"} {
		for _, format := range []string{"singbox", "srs"} {
			if _, err := Encode([]string{line}, format, "classical"); err == nil {
				t.Fatalf("lost semantics %s in %s", line, format)
			}
		}
	}
}

// The official CLI independently compiles our JSON. Its decompilation must be
// identical for that binary and ours, including matcher normalization and IP
// aggregation. It also exercises wildcard regex, Unicode, nested rules, ports.
func TestSingBoxCompatibility(t *testing.T) {
	bin := os.Getenv("SINGBOX_BIN")
	if bin == "" {
		t.Skip("set SINGBOX_BIN to official sing-box 1.14.1 executable")
	}
	version, err := exec.Command(bin, "version").CombinedOutput()
	if err != nil || !strings.Contains(string(version), "sing-box version 1.14.1") {
		t.Fatalf("expected sing-box 1.14.1: %s %v", version, err)
	}
	for _, behavior := range []string{"domain", "ipcidr", "classical", "empty"} {
		t.Run(behavior, func(t *testing.T) {
			lines := map[string][]string{
				"domain":    {"+.example.com", ".sub.example", "exact.example", "*.wild.example", "пример.рф", "foo.*.example.net"},
				"ipcidr":    {"192.0.2.0/25", "192.0.2.128/25", "10.0.0.0/8", "2001:db8::/32", "::1/128"},
				"classical": {"DOMAIN,example.com", "DOMAIN-SUFFIX,example.net", "DOMAIN-KEYWORD,keyword", "DOMAIN-REGEX,^test[0-9]+\\.example$", "IP-CIDR,192.0.2.0/24", "AND,((NETWORK,TCP),(OR,((DST-PORT,80),(DST-PORT,443))))", "NOT,((DOMAIN,blocked.example))", "SRC-IP-CIDR,10.0.0.0/8", "PROCESS-NAME,curl", "SRC-PORT,1024-65535"},
			}[behavior]
			if behavior == "empty" {
				behavior = "domain"
			}
			dir := t.TempDir()
			source, err := Encode(lines, "singbox", behavior)
			if err != nil {
				t.Fatal(err)
			}
			ours, err := Encode(lines, "srs", behavior)
			if err != nil {
				t.Fatal(err)
			}
			inputPath, oursPath, officialPath := filepath.Join(dir, "source.json"), filepath.Join(dir, "ours.srs"), filepath.Join(dir, "official.srs")
			if err := os.WriteFile(inputPath, source, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(oursPath, ours, 0600); err != nil {
				t.Fatal(err)
			}
			if out, err := exec.Command(bin, "rule-set", "compile", "--output", officialPath, inputPath).CombinedOutput(); err != nil {
				t.Fatalf("official compile: %v\n%s", err, out)
			}
			var recovered []any
			for _, path := range []string{oursPath, officialPath} {
				output := path + ".json"
				if out, err := exec.Command(bin, "rule-set", "decompile", "--output", output, path).CombinedOutput(); err != nil {
					t.Fatalf("official rejected SRS: %v\n%s", err, out)
				}
				b, err := os.ReadFile(output)
				if err != nil {
					t.Fatal(err)
				}
				var v any
				if err = json.Unmarshal(b, &v); err != nil {
					t.Fatal(err)
				}
				recovered = append(recovered, v)
			}
			if !reflect.DeepEqual(recovered[0], recovered[1]) {
				a, _ := json.Marshal(recovered[0])
				b, _ := json.Marshal(recovered[1])
				t.Fatalf("official meaning differs:\nours %s\nwant %s", a, b)
			}
		})
	}
}

func FuzzExtendedFormats(f *testing.F) {
	for _, seed := range [][]byte{[]byte("0.0.0.0 example.com"), []byte("||example.com^"), []byte(`{"version":2,"rules":[]}`), geoFixture("test", domainFixture(2, "example.com"))} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		for _, format := range []string{"hosts", "adblock", "geosite", "geoip", "singbox"} {
			_, _ = ParseSource(bytes.Clone(data), format, "classical", "*")
		}
	})
}
