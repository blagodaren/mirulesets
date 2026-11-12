package server

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/blagodaren/mirulesets/internal/config"
	"github.com/blagodaren/mirulesets/internal/model"
	"github.com/blagodaren/mirulesets/internal/service"
	"go.yaml.in/yaml/v3"
)

func TestSnippetPolicyPersistenceAndLegacyDefault(t *testing.T) {
	cfg := config.Config{DataDir: t.TempDir()}
	svc, err := service.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r, err := svc.Save(model.Ruleset{ID: "policy-test", Name: "Policy", Behavior: "domain", Policy: "Рабочая группа", CustomRules: []string{"example.com"}, IntervalSeconds: 60, Formats: []string{"text"}}, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Build(context.Background(), r.ID); err != nil {
		t.Fatal(err)
	}
	svc, err = service.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := &Server{svc: svc}
	checkPolicy := func(want string) {
		t.Helper()
		rec := httptest.NewRecorder()
		srv.snippet(rec, httptest.NewRequest("GET", "http://localhost/api/rulesets/policy-test/snippet?format=text", nil), r.ID)
		if rec.Code != 200 {
			t.Fatalf("snippet %d: %s", rec.Code, rec.Body.String())
		}
		var result struct {
			YAML string `json:"yaml"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		var parsed struct {
			Rules []string `yaml:"rules"`
		}
		if err := yaml.Unmarshal([]byte(result.YAML), &parsed); err != nil {
			t.Fatal(err)
		}
		if len(parsed.Rules) != 1 || parsed.Rules[0] != "RULE-SET,"+r.ID+","+want {
			t.Fatalf("snippet rules: %v", parsed.Rules)
		}
	}
	checkPolicy("Рабочая группа")
	// Old state files have no policy field. They keep the historical default.
	if err := svc.Store.Update(func(state *model.State) error {
		state.Rulesets[0].Policy = ""
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	checkPolicy("PROXY")
}
