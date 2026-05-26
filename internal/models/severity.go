package models

// Severity represents the severity level of a finding.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Score returns the numeric weight for the severity level.
func (s Severity) Score() int {
	switch s {
	case SeverityCritical:
		return 25
	case SeverityHigh:
		return 10
	case SeverityMedium:
		return 5
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

// String returns the string representation of the severity.
func (s Severity) String() string {
	return string(s)
}

// AllSeverities returns all severity levels in order from most to least severe.
func AllSeverities() []Severity {
	return []Severity{
		SeverityCritical,
		SeverityHigh,
		SeverityMedium,
		SeverityLow,
		SeverityInfo,
	}
}
