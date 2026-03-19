package models

// Category represents the category of a finding.
type Category string

const (
	CategorySpec     Category = "spec-compliance"
	CategorySecurity Category = "security"
	CategoryQuality  Category = "tool-quality"
)

// Location describes where a finding was detected.
type Location struct {
	File     string `json:"file,omitempty"`
	Line     int    `json:"line,omitempty"`
	ToolName string `json:"tool_name,omitempty"`
}

// Finding represents a single vulnerability or issue discovered during scanning.
type Finding struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Severity    Severity `json:"severity"`
	Category    Category `json:"category"`
	Location    Location `json:"location"`
	Remediation string   `json:"remediation"`
}

// AllCategories returns all finding categories.
func AllCategories() []Category {
	return []Category{
		CategorySpec,
		CategorySecurity,
		CategoryQuality,
	}
}
