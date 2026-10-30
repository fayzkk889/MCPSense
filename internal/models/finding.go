package models

// Category represents the category of a finding.
type Category string

const (
	CategorySpec     Category = "spec-compliance"
	CategorySecurity Category = "security"
	CategoryQuality  Category = "tool-quality"
	CategoryDrift    Category = "drift"
)

// Location describes where a finding was detected.
type Location struct {
	File     string `json:"file,omitempty"`
	Line     int    `json:"line,omitempty"`
	ToolName string `json:"tool_name,omitempty"`
}

// Finding represents a single vulnerability or issue discovered during scanning.
type Finding struct {
	Advisory    *AdvisoryEvidence `json:"advisory,omitempty"`
	Fingerprint string            `json:"fingerprint,omitempty"`
	Confidence  string            `json:"confidence,omitempty"`
	ID          string            `json:"id"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Severity    Severity          `json:"severity"`
	Category    Category          `json:"category"`
	OWASP       string            `json:"owasp,omitempty"`
	Location    Location          `json:"location"`
	Remediation string            `json:"remediation"`
	DiffOld     string            `json:"diff_old,omitempty"`
	DiffNew     string            `json:"diff_new,omitempty"`
}

// AdvisoryEvidence separates a feed match from a confirmed applicability
// decision. Conflicts retain both sources and require operator review.
type AdvisoryEvidence struct {
	ID            string `json:"id"`
	Applicability string `json:"applicability"`
	FeedURL       string `json:"feed_url"`
	ReviewedURL   string `json:"reviewed_url,omitempty"`
	ReviewedAt    string `json:"reviewed_at,omitempty"`
	ReviewNote    string `json:"review_note,omitempty"`
}

// AllCategories returns all finding categories.
func AllCategories() []Category {
	return []Category{
		CategorySpec,
		CategorySecurity,
		CategoryQuality,
		CategoryDrift,
	}
}
