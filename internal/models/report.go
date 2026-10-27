package models

import "time"

// Summary provides a breakdown of findings by severity, category, and OWASP risk.
type Summary struct {
	Total      int              `json:"total"`
	BySeverity map[Severity]int `json:"by_severity"`
	ByCategory map[Category]int `json:"by_category"`
	ByOWASP    map[string]int   `json:"by_owasp,omitempty"`
}

// Report aggregates all findings from a scan.
type Report struct {
	Assessment    SecurityAssessment   `json:"security_assessment"`
	TargetHash    string               `json:"target_hash"`
	MinSeverity   string               `json:"min_severity"`
	SchemaVersion int                  `json:"schema_version"`
	Coverage      Coverage             `json:"coverage"`
	Dependencies  *DependencyInventory `json:"dependencies,omitempty"`
	Target        string               `json:"target"`
	ScanMode      string               `json:"scan_mode"`
	Timestamp     time.Time            `json:"timestamp"`
	Findings      []Finding            `json:"findings"`
	Score         int                  `json:"score"`
	Summary       Summary              `json:"summary"`
}

// NewReport creates a Report and computes the summary and score.
func NewReport(target, scanMode string, findings []Finding) *Report {
	if findings == nil {
		findings = []Finding{}
	}
	// Populate the OWASP MCP Top 10 mapping for each finding based on its check ID.
	for i := range findings {
		if findings[i].OWASP == "" {
			findings[i].OWASP = OWASPForCheckID(findings[i].ID)
		}
	}

	r := &Report{
		SchemaVersion: 2,
		Coverage:      Coverage{State: "not_evaluated", Advisories: "not_evaluated"},
		Target:        target,
		ScanMode:      scanMode,
		Timestamp:     time.Now().UTC(),
		Findings:      findings,
	}
	r.computeSummary()
	r.Assessment = r.SecurityAssessment()
	r.CalculateScore()
	r.FinalizeEvidence()
	return r
}

// SecurityAssessment never turns a zero-finding heuristic scan into trust or
// authorization. It is separate from completion, finding score and exit status.
type SecurityAssessment struct {
	State                 string `json:"state"`
	AuthorizationEnforced bool   `json:"authorization_enforced"`
	Basis                 string `json:"basis"`
	Limitation            string `json:"limitation"`
}

func (r *Report) SecurityAssessment() SecurityAssessment {
	state := "not_established"
	if len(r.Findings) > 0 {
		state = "review_required"
	}
	return SecurityAssessment{State: state, Basis: "selected_checks_only", Limitation: "No safety or authorization verdict is established. Unknown phrasing and runtime behavior may be unassessed; enforce permissions in the host."}
}

func (r *Report) computeSummary() {
	bySeverity := make(map[Severity]int)
	byCategory := make(map[Category]int)
	byOWASP := make(map[string]int)

	for _, f := range r.Findings {
		bySeverity[f.Severity]++
		byCategory[f.Category]++
		if f.OWASP != "" {
			byOWASP[f.OWASP]++
		}
	}

	r.Summary = Summary{
		Total:      len(r.Findings),
		BySeverity: bySeverity,
		ByCategory: byCategory,
		ByOWASP:    byOWASP,
	}
}

// CalculateScore starts at 100 and subtracts severity-weighted penalties, floored at 0.
func (r *Report) CalculateScore() {
	score := 100
	for _, f := range r.Findings {
		score -= f.Severity.Score()
	}
	if score < 0 {
		score = 0
	}
	r.Score = score
}
