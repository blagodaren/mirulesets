package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/blagodaren/mirulesets/internal/config"
	"github.com/blagodaren/mirulesets/internal/model"
)

func TestSourceCredentialsRedactionAndPreservation(t *testing.T) {
	old := model.Ruleset{Sources: []model.Source{{ID: "a", Name: "private", URL: "https://example.com/rules", Headers: map[string]string{"Authorization": "Bearer secret"}}}}
	redacted := RedactRuleset(old)
	data, _ := json.Marshal(redacted)
	if strings.Contains(string(data), "Bearer secret") || len(redacted.Sources[0].HeaderNames) != 1 {
		t.Fatal("credential redaction failed")
	}
	preserveSourceHeaders(&redacted, old)
	if redacted.Sources[0].Headers["Authorization"] != "Bearer secret" {
		t.Fatal("redacted edit lost credentials")
	}
	redacted = RedactRuleset(old)
	redacted.Sources[0].URL = "https://other.example/rules"
	preserveSourceHeaders(&redacted, old)
	if len(redacted.Sources[0].Headers) != 0 {
		t.Fatal("new URL retained credential")
	}
	redacted = RedactRuleset(old)
	redacted.Sources[0].ClearHeaders = true
	preserveSourceHeaders(&redacted, old)
	if len(redacted.Sources[0].Headers) != 0 || len(old.Sources[0].Headers) != 1 {
		t.Fatal("explicit reset or detach failed")
	}
	declarative := model.Ruleset{Sources: []model.Source{{Name: "private", URL: "https://example.com/rules"}}}
	preserveSourceHeaders(&declarative, old)
	if declarative.Sources[0].ID != "a" || declarative.Sources[0].Headers["Authorization"] != "Bearer secret" {
		t.Fatal("declarative application lost identity or credentials")
	}
}

func TestAuthenticatedParseErrorsNeverExposeReflectedToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("token-fragment/path\n")) }))
	defer srv.Close()
	s, err := New(config.Config{DataDir: t.TempDir(), AllowPrivateSources: true})
	if err != nil {
		t.Fatal(err)
	}
	_, status, err := s.sourceWithStatus(context.Background(), model.Source{URL: srv.URL, Format: "text", Behavior: "domain", Headers: map[string]string{"Authorization": "Bearer token-fragment"}})
	if err == nil || strings.Contains(err.Error(), "token-fragment") || strings.Contains(status.Error, "token-fragment") {
		t.Fatalf("reflected secret leaked: %v %+v", err, status)
	}
}

func TestRulesetSourceBuildUsesPublishedGenerationAndRejectsCycle(t *testing.T) {
	s, err := New(config.Config{DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	base, err := s.Save(model.Ruleset{ID: "base", Name: "Base", Behavior: "domain", CustomRules: []string{"+.example.com"}, IntervalSeconds: 60, Formats: []string{"text"}}, true)
	if err != nil {
		t.Fatal(err)
	}
	base, err = s.Build(context.Background(), base.ID)
	if err != nil {
		t.Fatal(err)
	}
	derived, err := s.Save(model.Ruleset{ID: "derived", Name: "Derived", Behavior: "classical", Sources: []model.Source{{URL: "ruleset://base", Behavior: "domain", Enabled: true}}, IntervalSeconds: 60, Formats: []string{"text"}}, true)
	if err != nil {
		t.Fatal(err)
	}
	derived, err = s.Build(context.Background(), derived.ID)
	if err != nil {
		t.Fatal(err)
	}
	lines, err := s.generationRules(derived.ID, derived.LastBuild)
	if err != nil || !slices.Equal(lines, []string{"DOMAIN-SUFFIX,example.com"}) {
		t.Fatalf("derived %v %v", lines, err)
	}
	base.CustomRules = []string{"edited.example"}
	base, err = s.Save(base, false)
	if err != nil {
		t.Fatal(err)
	}
	derived, err = s.Build(context.Background(), derived.ID)
	if err != nil || derived.LastBuild.RuleCount != 1 {
		t.Fatalf("%+v %v", derived.LastBuild, err)
	}
	lines, err = s.generationRules(derived.ID, derived.LastBuild)
	if err != nil || !slices.Equal(lines, []string{"DOMAIN-SUFFIX,example.com"}) {
		t.Fatalf("unpublished edits consumed: %v %v", lines, err)
	}
	base.Sources = []model.Source{{URL: "ruleset://derived", Behavior: "classical", Enabled: false}}
	if _, err = s.Save(base, false); err == nil {
		t.Fatal("disabled cyclic dependency accepted")
	}
	if err = s.Delete(base.ID); err == nil {
		t.Fatal("referenced ruleset deleted")
	}
}

func TestDependencyGraphRejectsCyclesAndMissingNodes(t *testing.T) {
	sets := []model.Ruleset{{ID: "a", Sources: []model.Source{{URL: "ruleset://b"}}}, {ID: "b"}}
	if err := validateDependencies(sets); err != nil {
		t.Fatal(err)
	}
	sets[1].Sources = []model.Source{{URL: "ruleset://a"}}
	if validateDependencies(sets) == nil {
		t.Fatal("cycle accepted")
	}
	sets[1].Sources = nil
	if validateDependencies(sets[:1]) == nil {
		t.Fatal("missing dependency accepted")
	}
	for _, raw := range []string{"ruleset://a/../b", "ruleset://a?x=1", "ruleset://user@a", "ruleset://a:80"} {
		if _, err := rulesetSourceID(raw); err == nil {
			t.Fatalf("unsafe dependency accepted: %s", raw)
		}
	}
}

func TestSourceHeadersFilterAndLatestStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret" {
			w.WriteHeader(401)
			return
		}
		if r.Header.Get("If-None-Match") == `"ok"` {
			w.WriteHeader(304)
			return
		}
		w.Header().Set("ETag", `"ok"`)
		_, _ = w.Write([]byte("+.keep.test\nother.test\n+.skip.keep.test\n"))
	}))
	defer srv.Close()
	s, err := New(config.Config{DataDir: t.TempDir(), AllowPrivateSources: true})
	if err != nil {
		t.Fatal(err)
	}
	src := model.Source{URL: srv.URL, Format: "text", Behavior: "domain", Headers: map[string]string{"Authorization": "Bearer secret"}, IncludeRegex: `keep\.test$`, ExcludeRegex: `skip`}
	for _, wantStatus := range []int{200, 304} {
		lines, status, err := s.sourceWithStatus(context.Background(), src)
		if err != nil || !slices.Equal(lines, []string{"+.keep.test"}) || status.HTTPStatus != wantStatus || status.RuleCount != 1 || status.FetchedAt.IsZero() {
			t.Fatalf("lines=%v status=%+v error=%v", lines, status, err)
		}
	}
	src.Headers = nil
	_, status, err := s.sourceWithStatus(context.Background(), src)
	if err == nil || status.HTTPStatus != 401 || status.Error == "" {
		t.Fatal("missing failure status")
	}
}

func TestASNResponseRejectsTruncationAndCrossFamily(t *testing.T) {
	valid := `{"status":"ok","status_code":200,"data":{"resource":"13335","list_prefixes":true,"counts":{"v4":{"originating":1},"v6":{"originating":1}},"prefixes":{"v4":{"originating":["1.1.1.0/24"]},"v6":{"originating":["2606:4700::/32"]}}}}`
	lines, err := parseASNResponse([]byte(valid), "AS13335")
	if err != nil || len(lines) != 2 {
		t.Fatalf("%v %v", lines, err)
	}
	for _, bad := range []string{strings.Replace(valid, `"originating":1`, `"originating":2`, 1), strings.Replace(valid, "1.1.1.0/24", "::/32", 1), strings.Replace(valid, `"resource":"13335"`, `"resource":"3333"`, 1), strings.Replace(valid, `"list_prefixes":true`, `"list_prefixes":false`, 1)} {
		if _, err := parseASNResponse([]byte(bad), "AS13335"); err == nil {
			t.Fatal("invalid ASN response accepted")
		}
	}
	for _, bad := range []string{"AS0", "AS4294967296", "AS1?token=secret", "https://example.com"} {
		if _, err := normalizeASN(bad); err == nil {
			t.Fatalf("invalid ASN accepted: %s", bad)
		}
	}
}

func TestSourceRegexAndHeaderValidation(t *testing.T) {
	src := model.Source{URL: "https://example.com", Format: "text", Behavior: "domain", IncludeRegex: "["}
	if ValidateSource(&src, "domain") == nil {
		t.Fatal("invalid regex accepted")
	}
	src.IncludeRegex = ""
	src.Headers = map[string]string{"Authorization": "secret\n"}
	if ValidateSource(&src, "domain") == nil {
		t.Fatal("invalid header accepted")
	}
	src.Headers = nil
	src.URL = "AS13335"
	src.Format = "asn"
	if ValidateSource(&src, "domain") == nil {
		t.Fatal("domain ASN accepted")
	}
	src.Behavior = "ipcidr"
	if err := ValidateSource(&src, "ipcidr"); err != nil {
		t.Fatal(err)
	}
}
