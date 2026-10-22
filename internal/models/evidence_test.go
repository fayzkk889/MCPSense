package models

import "testing"

func evidenceReport(fs []Finding) *Report {
	r := NewReport("target", "manifest", fs)
	r.MinSeverity = "low"
	r.Coverage = Coverage{State: "completed", Surfaces: []string{"manifest"}, Inputs: []string{"same"}, SelectedChecks: []string{"SEC-001"}, Advisories: "skipped"}
	r.FinalizeEvidence()
	return r
}
func TestVerificationRequiresEquivalentCompleteCoverage(t *testing.T) {
	old := evidenceReport([]Finding{{ID: "SEC-001", Location: Location{ToolName: "read"}}})
	now := evidenceReport(nil)
	v, err := VerifyReports(old, now)
	if err != nil || len(v.Resolved) != 1 {
		t.Fatalf("failed comparison: %+v %v", v, err)
	}
	for _, change := range []func(*Report){func(r *Report) { r.Coverage.State = "failed" }, func(r *Report) { r.Coverage.Inputs = []string{"changed"} }, func(r *Report) { r.MinSeverity = "high" }, func(r *Report) { r.TargetHash = "different" }, func(r *Report) { r.Coverage.Advisories = "completed" }} {
		r := evidenceReport(nil)
		change(r)
		if _, err := VerifyReports(old, r); err == nil {
			t.Fatal("incomparable scan resolved a finding")
		}
	}
}
func TestStableRuleComponentIdentity(t *testing.T) {
	a := evidenceReport([]Finding{{ID: "SEC-002", Location: Location{File: "server.go", Line: 1}}})
	b := evidenceReport([]Finding{{ID: "SEC-002", Location: Location{File: "server.go", Line: 7}}})
	if a.Findings[0].Fingerprint != b.Findings[0].Fingerprint {
		t.Fatal("line movement changed component identity")
	}
	v, err := VerifyReports(a, b)
	if err != nil || len(v.Persistent) != 1 || len(v.Resolved) != 0 {
		t.Fatalf("wrong persistence: %+v %v", v, err)
	}
}
func TestAcceptingNewBaselineIsNotRemediation(t *testing.T) {
	before := evidenceReport([]Finding{{ID: "DRIFT-002", Location: Location{ToolName: "synthetic"}}})
	after := evidenceReport(nil)
	before.Coverage.Baseline = "compared"
	after.Coverage.Baseline = "compared"
	before.Coverage.BaselineHash = "old-approved-snapshot"
	after.Coverage.BaselineHash = "new-approved-snapshot"
	if _, err := VerifyReports(before, after); err == nil {
		t.Fatal("baseline reapproval was mistaken for remediation")
	}
}
