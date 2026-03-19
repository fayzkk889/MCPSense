package models

import "time"

// Summary provides a breakdown of findings by severity and category.
type Summary struct {
	Total      int              `json:"total"`
	BySeverity map[Severity]int `json:"by_severity"`
	ByCategory map[Category]int `json:"by_category"`
}

// Report aggregates all findings from a scan.
type Report struct {
	Target    string    `json:"target"`
	ScanMode  string    `json:"scan_mode"`
	Timestamp time.Time `json:"timestamp"`
	Findings  []Finding `json:"findings"`
	Score     int       `json:"score"`
	Summary   Summary   `json:"summary"`
}

// NewReport creates a Report and computes the summary and score.
func NewReport(target, scanMode string, findings []Finding) *Report {
	r := &Report{
		Target:    target,
		ScanMode:  scanMode,
		Timestamp: time.Now().UTC(),
		Findings:  findings,
	}
	r.computeSummary()
	r.CalculateScore()
	return r
}

func (r *Report) computeSummary() {
	bySeverity := make(map[Severity]int)
	byCategory := make(map[Category]int)

	for _, f := range r.Findings {
		bySeverity[f.Severity]++
		byCategory[f.Category]++
	}

	r.Summary = Summary{
		Total:      len(r.Findings),
		BySeverity: bySeverity,
		ByCategory: byCategory,
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
