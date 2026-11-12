package service

import (
	"context"
	"net/netip"
	"testing"

	"github.com/blagodaren/mirulesets/internal/config"
	"github.com/blagodaren/mirulesets/internal/model"
)

func TestDomainLookupDistinguishesWildcardSemantics(t *testing.T) {
	for _, test := range []struct {
		pattern, domain string
		want            bool
	}{
		{"+.example.com", "example.com", true}, {"+.example.com", "a.b.example.com", true}, {".example.com", "example.com", false}, {".example.com", "a.b.example.com", true}, {"*.example.com", "a.b.example.com", false}, {"*.example.com", "a.example.com", true}, {"*.example.com", "example.com", false}, {"+.example.com", "otherexample.com", false}, {"*", "localhost", true},
	} {
		if got := matchDomainPattern(test.pattern, test.domain); got != test.want {
			t.Errorf("%s %s = %t", test.pattern, test.domain, got)
		}
	}
	if got, supported := lookupRule("DOMAIN-WILDCARD,*.example.com", "classical", "a.b.example.com", netip.Addr{}); !got || !supported {
		t.Fatal("classical wildcard incorrectly limited to one label")
	}
	if got, supported := lookupRule(`DOMAIN-REGEX,^(?=www\.)www\.example\.com$`, "classical", "www.example.com", netip.Addr{}); !got || !supported {
		t.Fatal("classical regex failed")
	}
	if got, supported := lookupRule("IP-CIDR,1.1.1.0/24,src", "classical", "", netip.MustParseAddr("1.1.1.1")); got || supported {
		t.Fatal("source IP matched destination")
	}
}

func TestLookupUsesPublishedRulesAndReportsUnknown(t *testing.T) {
	s, err := New(config.Config{DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.Save(model.Ruleset{ID: "lookup", Name: "Lookup", Behavior: "classical", CustomRules: []string{"DOMAIN-SUFFIX,example.com", "IP-CIDR,1.1.1.0/24", "PROCESS-NAME,browser"}, IntervalSeconds: 60, Formats: []string{"text"}}, true)
	if err != nil {
		t.Fatal(err)
	}
	r, err = s.Build(context.Background(), r.ID)
	if err != nil {
		t.Fatal(err)
	}
	r.CustomRules = []string{"DOMAIN,unpublished.test"}
	if _, err = s.Save(r, false); err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{"WWW.EXAMPLE.COM.", "1.1.1.1", "::ffff:1.1.1.1"} {
		matches, err := s.Lookup(query)
		if err != nil || len(matches) != 1 || matches[0].MatchCount != 1 || matches[0].UnsupportedRules != 1 {
			t.Fatalf("%s: %+v %v", query, matches, err)
		}
	}
	for _, query := range []string{"", "https://example.com", "*.example.com", "1.1.1.1:443", "a..example"} {
		if _, err := s.Lookup(query); err == nil {
			t.Fatalf("invalid lookup accepted: %s", query)
		}
	}
	matches, err := s.Lookup("unpublished.test")
	if err != nil || len(matches) != 1 || matches[0].MatchCount != 0 || matches[0].UnsupportedRules != 1 {
		t.Fatalf("edited rules appeared as published: %+v %v", matches, err)
	}
}
