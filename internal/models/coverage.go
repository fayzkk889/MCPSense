package models

// Coverage describes only the explicitly evaluated scope, never overall security.
type Coverage struct {
	DetectorProfile string   `json:"detector_profile"`
	MetadataFields  []string `json:"metadata_fields,omitempty"`
	Unassessed      []string `json:"unassessed,omitempty"`
	Inputs          []string `json:"inputs"`
	Protocol        string   `json:"protocol,omitempty"`
	Baseline        string   `json:"baseline"`
	BaselineHash    string   `json:"baseline_hash,omitempty"`
	State           string   `json:"state"`
	Surfaces        []string `json:"surfaces"`
	SelectedChecks  []string `json:"selected_checks"`
	SkippedChecks   []string `json:"skipped_checks"`
	Advisories      string   `json:"advisories"`
}
