package models

import "testing"

func TestNoFindingOrScoreCanEstablishSecurity(t *testing.T) {
	r := NewReport("fixture", "manifest", nil)
	if r.Score != 100 || r.Assessment.State != "not_established" || r.Assessment.AuthorizationEnforced {
		t.Fatal("clean score asserted safety", r.Assessment)
	}
	r.Findings = []Finding{{ID: "SEC-001", Severity: SeverityHigh, Category: CategorySecurity}}
	if r.ProtectedCopy(nil).Assessment.State != "review_required" {
		t.Fatal("findings lost review state")
	}
	r.Findings = nil
	r.Assessment = SecurityAssessment{State: "safe", AuthorizationEnforced: true}
	if r.ProtectedCopy(nil).Assessment.State != "not_established" || r.ProtectedCopy(nil).Assessment.AuthorizationEnforced {
		t.Fatal("copied report retained an unsupported safety claim")
	}
}
