package rules

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
)

func TestParseFormats(t *testing.T) {
	for _, format := range []string{"yaml", "text", "mrs"} {
		for _, behavior := range []string{"domain", "ipcidr", "classical"} {
			if format == "mrs" && behavior == "classical" {
				continue
			}
			t.Run(format+"/"+behavior, func(t *testing.T) {
				lines := map[string][]string{
					"domain":    {"+.example.com", "single.example.net", "*.example.org", ".only.example", "sub.*.example", "пример.рф"},
					"ipcidr":    {"10.0.0.0/8", "2001:db8::/32"},
					"classical": {"DOMAIN-SUFFIX,example.com", "IP-CIDR,10.0.0.0/8,no-resolve", "AND,((NETWORK,TCP),(DST-PORT,443))"},
				}[behavior]
				encoded, err := Encode(lines, format, behavior)
				if err != nil {
					t.Fatal(err)
				}
				got, err := Parse(encoded, format, behavior)
				if err != nil {
					t.Fatal(err)
				}
				assertSameRules(t, lines, got)
			})
		}
	}
}

func TestNormalizationPreservesClassicalOrder(t *testing.T) {
	got, err := Parse([]byte("# comment\n\nDOMAIN,First.Example\nDOMAIN,second.example\nDOMAIN,First.Example\n// comment\n"), "text", "classical")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"DOMAIN,first.example", "DOMAIN,second.example"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	got, err = Normalize([]string{"192.0.2.123/24", "192.0.2.0/24"}, "ipcidr")
	if err != nil || !reflect.DeepEqual(got, []string{"192.0.2.0/24"}) {
		t.Fatalf("CIDR normalization: %v %v", got, err)
	}
}

func TestAutoDetection(t *testing.T) {
	for _, format := range []string{"text", "yaml", "mrs"} {
		data, err := Encode([]string{"+.example.com"}, format, "domain")
		if err != nil {
			t.Fatal(err)
		}
		got, err := Parse(data, "auto", "domain")
		if err != nil {
			t.Fatal(err)
		}
		assertSameRules(t, []string{"+.example.com"}, got)
	}
	for _, data := range []string{"# comments\nname: anything\npayload:\n  - '+.example.com'\n", "{payload: ['+.example.com']}"} {
		got, err := Parse([]byte(data), "auto", "domain")
		if err != nil {
			t.Fatal(err)
		}
		assertSameRules(t, []string{"+.example.com"}, got)
	}
}

func TestBareIPAddresses(t *testing.T) {
	got, err := Parse([]byte("# Antifilter-compatible list\n192.0.2.1\n2001:db8::1\n192.0.2.1/32\n"), "auto", "ipcidr")
	if err != nil {
		t.Fatal(err)
	}
	assertSameRules(t, []string{"192.0.2.1/32", "2001:db8::1/128"}, got)
	if _, err := Parse([]byte("fe80::1%eth0"), "text", "ipcidr"); err == nil {
		t.Fatal("accepted scoped IPv6")
	}
}

func TestRejectInvalidInputs(t *testing.T) {
	cases := []struct{ input, format, behavior string }{
		{"payload: [*.example.com]", "yaml", "domain"},
		{"payload: [123]", "yaml", "domain"},
		{"payload: ['example.com']\n---\npayload: ['other.com']", "yaml", "domain"},
		{"payload: &x ['example.com']\nrules: *x", "yaml", "domain"},
		{"rules: ['DOMAIN,example.com']\npayload: ['example.com']", "yaml", "domain"},
		{"a..b", "text", "domain"},
		{"a*b.example", "text", "domain"},
		{"https://example.com", "text", "domain"},
		{"192.0.2.1/99", "text", "ipcidr"},
		{"MATCH", "text", "classical"},
		{"RULE-SET,other", "text", "classical"},
		{"DOMAIN,example.com,Proxy", "text", "classical"},
		{"DST-PORT,65536", "text", "classical"},
		{"DSCP,64", "text", "classical"},
		{"NETWORK,ICMP", "text", "classical"},
		{"DOMAIN-REGEX,([", "text", "classical"},
		{"NOT,((DOMAIN,a),(DOMAIN,b))", "text", "classical"},
		{"AND,((DOMAIN,a),)", "text", "classical"},
		{"AND,((DOMAIN,a)", "text", "classical"},
		{"example.com", "json", "domain"},
		{"example.com", "text", "unknown"},
		{"x", "mrs", "classical"},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			if _, err := Parse([]byte(tc.input), tc.format, tc.behavior); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestAllClassicalRuleTypes(t *testing.T) {
	lines := []string{
		"DOMAIN,example.com", "DOMAIN-SUFFIX,example.com", "DOMAIN-KEYWORD,example", "DOMAIN-WILDCARD,*.example.com",
		`DOMAIN-REGEX,^(?=.{1,253}$)(?:www\.)?example\.com$`, "GEOSITE,google", "GEOIP,CN,no-resolve", "SRC-GEOIP,CN",
		"IP-ASN,64512,no-resolve", "SRC-IP-ASN,64512", "IP-CIDR,10.0.0.0/8,src", "IP-CIDR6,2001:db8::/32", "SRC-IP-CIDR,10.0.0.0/8",
		"IP-SUFFIX,0.0.0.1/8,no-resolve", "SRC-IP-SUFFIX,::1/16", "SRC-PORT,80/443/8000-8080", "DST-PORT,443", "IN-PORT,7890", "DSCP,0-63", "DSCP,*",
		"PROCESS-NAME,chrome.exe", "PROCESS-PATH,/usr/bin/curl", "PROCESS-NAME-REGEX,chrome.*", "PROCESS-PATH-REGEX,/usr/.*/curl",
		"PROCESS-NAME-WILDCARD,chrome*", "PROCESS-PATH-WILDCARD,/usr/*", "NETWORK,TCP", "UID,1000-1005/2000",
		"IN-TYPE,HTTP/SOCKS/SHADOWQUIC", "IN-USER,alice", "IN-NAME,mixed-in", "REMATCH-NAME,stage-two",
		"AND,((NETWORK,TCP),(DST-PORT,443))", "OR,((DOMAIN,a),(DOMAIN,b))", "NOT,((DOMAIN,example.com))",
		"AND,((NETWORK,TCP),(OR,((DOMAIN,a),(DOMAIN,b))))", "AND,((RULE-SET,other),(NETWORK,TCP))",
	}
	for _, line := range lines {
		if _, err := Normalize([]string{line}, "classical"); err != nil {
			t.Errorf("%s: %v", line, err)
		}
	}
}

func TestTransformIsLosslessOrErrors(t *testing.T) {
	got, err := Transform([]string{"+.example.com", "example.net", "*.example.org", ".example.edu"}, "domain", "classical")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"DOMAIN-SUFFIX,example.com", "DOMAIN,example.net", `DOMAIN-REGEX,^[^.]+\.example\.org$`, `DOMAIN-REGEX,^(?:[^.]+\.)+example\.edu$`}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	got, err = Transform([]string{"DOMAIN-SUFFIX,example.com", "DOMAIN,example.net"}, "classical", "domain")
	if err != nil {
		t.Fatal(err)
	}
	assertSameRules(t, []string{"+.example.com", "example.net"}, got)
	for _, line := range []string{"DOMAIN-KEYWORD,example", "IP-CIDR,10.0.0.0/8", "DOMAIN-WILDCARD,*.example.com"} {
		if _, err := Transform([]string{line}, "classical", "domain"); err == nil {
			t.Errorf("lossy conversion accepted: %s", line)
		}
	}
	for _, line := range []string{"IP-CIDR,10.0.0.0/8,no-resolve", "IP-CIDR,10.0.0.0/8,src", "SRC-IP-CIDR,10.0.0.0/8"} {
		if _, err := Transform([]string{line}, "classical", "ipcidr"); err == nil {
			t.Errorf("lost source/no-resolve semantics: %s", line)
		}
	}
}

func TestMRSRejectsMalformedData(t *testing.T) {
	valid, err := Encode([]string{"+.example.com"}, "mrs", "domain")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(valid); i++ {
		if _, err := Parse(valid[:i], "mrs", "domain"); err == nil {
			t.Fatalf("accepted truncation at byte %d", i)
		}
	}
	if _, err := Parse(valid, "mrs", "ipcidr"); err == nil {
		t.Fatal("accepted wrong behavior")
	}
	decoder, _ := zstd.NewReader(nil)
	raw, err := decoder.DecodeAll(valid, nil)
	decoder.Close()
	if err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []func([]byte){
		func(b []byte) { b[0] = 'X' },
		func(b []byte) { b[4] = 2 },
		func(b []byte) { binary.BigEndian.PutUint64(b[5:13], 0) },
		func(b []byte) { binary.BigEndian.PutUint64(b[13:21], ^uint64(0)) },
		func(b []byte) { b[21] = 99 },
		func(b []byte) { binary.BigEndian.PutUint64(b[22:30], ^uint64(0)) },
		func(b []byte) { b[37] |= 1 }, // Mark the root terminal.
	} {
		modified := bytes.Clone(raw)
		mutation(modified)
		if _, err := Parse(compressFixture(t, modified), "mrs", "domain"); err == nil {
			t.Fatal("accepted malformed MRS")
		}
	}
	if _, err := Parse(compressFixture(t, append(bytes.Clone(raw), 0)), "mrs", "domain"); err == nil {
		t.Fatal("accepted trailing bytes")
	}
}

func TestMRSIPRangeValidation(t *testing.T) {
	var raw bytes.Buffer
	raw.Write(mrsMagic)
	raw.WriteByte(1)
	writeInt(&raw, 1)
	writeInt(&raw, 0)
	raw.WriteByte(1)
	writeInt(&raw, 1)
	raw.Write(bytes.Repeat([]byte{0xff}, 16))
	raw.Write(make([]byte, 16))
	if _, err := Parse(compressFixture(t, raw.Bytes()), "mrs", "ipcidr"); err == nil {
		t.Fatal("accepted reversed range")
	}
}

func compressFixture(t *testing.T, data []byte) []byte {
	t.Helper()
	encoder, err := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1))
	if err != nil {
		t.Fatal(err)
	}
	defer encoder.Close()
	return encoder.EncodeAll(data, nil)
}

func assertSameRules(t *testing.T, want, got []string) {
	t.Helper()
	want = append([]string(nil), want...)
	got = append([]string(nil), got...)
	sort.Strings(want)
	sort.Strings(got)
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// MIHOMO_BIN must point to the official pinned v1.19.34 binary. The check is
// opt-in in normal CI and exercises both conversion directions, independently
// of this codec's own round-trip tests.
func TestMihomoCompatibility(t *testing.T) {
	bin := os.Getenv("MIHOMO_BIN")
	if bin == "" {
		t.Skip("set MIHOMO_BIN to the official Mihomo v1.19.34 executable")
	}
	version, err := exec.Command(bin, "-v").CombinedOutput()
	if err != nil || !strings.Contains(string(version), "v1.19.34") {
		t.Fatalf("expected Mihomo v1.19.34: %s %v", version, err)
	}
	for _, behavior := range []string{"domain", "ipcidr"} {
		t.Run(behavior, func(t *testing.T) {
			lines := map[string][]string{
				"domain": {"+.example.com", ".suffix-only.example", "exact.example", "*.wild.example", "foo.*.example.net", "пример.рф"},
				"ipcidr": {"192.0.2.0/25", "192.0.2.128/25", "10.0.0.0/8", "2001:db8::/32", "::1/128"},
			}[behavior]
			dir := t.TempDir()
			ours, err := Encode(lines, "mrs", behavior)
			if err != nil {
				t.Fatal(err)
			}
			ourPath := filepath.Join(dir, "ours.mrs")
			if err := os.WriteFile(ourPath, ours, 0600); err != nil {
				t.Fatal(err)
			}
			textPath := filepath.Join(dir, "export.txt")
			if out, err := exec.Command(bin, "convert-ruleset", behavior, "mrs", ourPath, textPath).CombinedOutput(); err != nil {
				t.Fatalf("Mihomo rejected our MRS: %v\n%s", err, out)
			}
			textData, err := os.ReadFile(textPath)
			if err != nil {
				t.Fatal(err)
			}
			fromMihomo, err := Parse(textData, "text", behavior)
			if err != nil {
				t.Fatal(err)
			}
			ourCanonical, err := Parse(ours, "mrs", behavior)
			if err != nil {
				t.Fatal(err)
			}
			assertSameRules(t, ourCanonical, fromMihomo)
			for _, inputFormat := range []string{"yaml", "text"} {
				input, err := Encode(lines, inputFormat, behavior)
				if err != nil {
					t.Fatal(err)
				}
				inputPath := filepath.Join(dir, "input."+inputFormat)
				if err := os.WriteFile(inputPath, input, 0600); err != nil {
					t.Fatal(err)
				}
				target := filepath.Join(dir, "official-"+inputFormat+".mrs")
				if out, err := exec.Command(bin, "convert-ruleset", behavior, inputFormat, inputPath, target).CombinedOutput(); err != nil {
					t.Fatalf("Mihomo conversion failed: %v\n%s", err, out)
				}
				data, err := os.ReadFile(target)
				if err != nil {
					t.Fatal(err)
				}
				got, err := Parse(data, "mrs", behavior)
				if err != nil {
					t.Fatal(err)
				}
				assertSameRules(t, ourCanonical, got)
			}
		})
	}
}

func BenchmarkDomainMRS100K(b *testing.B) {
	lines := make([]string, 100_000)
	for i := range lines {
		lines[i] = fmt.Sprintf("+.host-%d.example.com", i)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Encode(lines, "mrs", "domain"); err != nil {
			b.Fatal(err)
		}
	}
}

func TestOfficialMRSFixtures(t *testing.T) {
	bin, fixtures := os.Getenv("MIHOMO_BIN"), os.Getenv("MIHOMO_FIXTURES")
	if bin == "" || fixtures == "" {
		t.Skip("set MIHOMO_BIN and MIHOMO_FIXTURES for upstream dataset checks")
	}
	for _, fixture := range []struct{ name, behavior string }{{"google", "domain"}, {"telegram", "ipcidr"}} {
		t.Run(fixture.name, func(t *testing.T) {
			path := filepath.Join(fixtures, fixture.name+".mrs")
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			got, err := Parse(data, "auto", fixture.behavior)
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			dump := filepath.Join(dir, "official.txt")
			if out, err := exec.Command(bin, "convert-ruleset", fixture.behavior, "mrs", path, dump).CombinedOutput(); err != nil {
				t.Fatalf("Mihomo failed: %v\n%s", err, out)
			}
			textData, err := os.ReadFile(dump)
			if err != nil {
				t.Fatal(err)
			}
			want, err := Parse(textData, "text", fixture.behavior)
			if err != nil {
				t.Fatal(err)
			}
			assertSameRules(t, want, got)
			rebuilt, err := Encode(got, "mrs", fixture.behavior)
			if err != nil {
				t.Fatal(err)
			}
			rebuiltPath := filepath.Join(dir, "rebuilt.mrs")
			if err := os.WriteFile(rebuiltPath, rebuilt, 0600); err != nil {
				t.Fatal(err)
			}
			if out, err := exec.Command(bin, "convert-ruleset", fixture.behavior, "mrs", rebuiltPath, dump).CombinedOutput(); err != nil {
				t.Fatalf("Mihomo rejected rebuilt fixture: %v\n%s", err, out)
			}
			textData, err = os.ReadFile(dump)
			if err != nil {
				t.Fatal(err)
			}
			want, err = Parse(textData, "text", fixture.behavior)
			if err != nil {
				t.Fatal(err)
			}
			assertSameRules(t, want, got)
			t.Logf("%s: %d compressed bytes, %d rules, %d rebuilt bytes", fixture.name, len(data), len(got), len(rebuilt))
		})
	}
}
