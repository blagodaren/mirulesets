package server

import (
	"context"
	"net/http/httptest"
	"testing"
)

func TestResumeRequiresAuthenticationAndDoesNotBuild(t *testing.T) {
	svc, h, call := featureServer(t)
	r, err := svc.Save(featureSet("resume"), true)
	if err != nil {
		t.Fatal(err)
	}
	r, err = svc.Build(context.Background(), r.ID)
	if err != nil {
		t.Fatal(err)
	}
	r.CustomRules = append(r.CustomRules, "new.test")
	r, err = svc.Save(r, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Build(context.Background(), r.ID); err != nil {
		t.Fatal(err)
	}
	r, err = svc.Rollback(context.Background(), r.ID)
	if err != nil {
		t.Fatal(err)
	}
	before := r.LastBuild.Generation
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/api/rulesets/resume/resume", nil))
	if rec.Code != 401 {
		t.Fatalf("unauthorized resume = %d", rec.Code)
	}
	call("POST", "/api/rulesets/resume/resume", nil, 200)
	r, _ = svc.Store.Get(r.ID)
	if r.RollbackHold || r.LastBuild.Generation != before {
		t.Fatalf("resume publication: %+v", r)
	}
	call("POST", "/api/rulesets/resume/resume", nil, 200)
	call("POST", "/api/rulesets/missing/resume", nil, 404)
}
