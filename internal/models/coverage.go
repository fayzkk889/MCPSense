package models

// Coverage describes only the explicitly evaluated scope, never overall security.
type Coverage struct {
	State          string   `json:"state"`
	Surfaces       []string `json:"surfaces"`
	SelectedChecks []string `json:"selected_checks"`
	SkippedChecks  []string `json:"skipped_checks"`
	Advisories     string   `json:"advisories"`
}
