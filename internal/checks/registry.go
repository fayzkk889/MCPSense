package checks

import (
	"github.com/fayzkk889/MCPSense/internal/detection"
	"github.com/fayzkk889/MCPSense/internal/models"
)

// ScanContext holds all input data available to checks during a scan.
type ScanContext struct {
	Manifest    *models.MCPManifest
	SourceFiles map[string]string
	Patterns    *detection.PatternEngine
}

// Check defines the interface all checks must implement.
type Check interface {
	ID() string
	Name() string
	Category() models.Category
	Run(ctx *ScanContext) []models.Finding
}

// Registry holds all registered checks and runs them.
type Registry struct {
	checks []Check
}

// NewRegistry creates a Registry pre-loaded with all built-in checks.
func NewRegistry() *Registry {
	r := &Registry{}

	// Spec compliance checks
	r.Register(&SpecManifestStructureCheck{})
	r.Register(&SpecToolSchemaCheck{})
	r.Register(&SpecToolNamingCheck{})
	r.Register(&SpecResourceURICheck{})
	r.Register(&SpecProtocolVersionCheck{})

	// Security checks
	r.Register(&InjectionCheck{})
	r.Register(&ShellExecCheck{})
	r.Register(&SSRFCheck{})
	r.Register(&PathTraversalCheck{})
	r.Register(&MissingAuthCheck{})
	r.Register(&ResourceScopeCheck{})
	r.Register(&CommandInjectionCheck{})
	r.Register(&DataExfilCheck{})

	// Tool quality checks
	r.Register(&DescriptionClarityCheck{})
	r.Register(&AmbiguousParamCheck{})
	r.Register(&MissingParamDescCheck{})
	r.Register(&DuplicateToolCheck{})
	r.Register(&MissingExamplesCheck{})
	r.Register(&ExcessiveToolCountCheck{})

	return r
}

// Register adds a check to the registry.
func (r *Registry) Register(c Check) {
	r.checks = append(r.checks, c)
}

// RunAll executes all checks and returns combined findings.
func (r *Registry) RunAll(ctx *ScanContext) []models.Finding {
	var findings []models.Finding
	for _, c := range r.checks {
		findings = append(findings, c.Run(ctx)...)
	}
	return findings
}

// RunByIDs executes only the checks with the given IDs.
func (r *Registry) RunByIDs(ctx *ScanContext, ids []string) []models.Finding {
	idSet := make(map[string]bool, len(ids))
	for _, id := range ids {
		idSet[id] = true
	}
	var findings []models.Finding
	for _, c := range r.checks {
		if idSet[c.ID()] {
			findings = append(findings, c.Run(ctx)...)
		}
	}
	return findings
}

// RunExcluding executes all checks except those with the given IDs.
func (r *Registry) RunExcluding(ctx *ScanContext, excludeIDs []string) []models.Finding {
	excludeSet := make(map[string]bool, len(excludeIDs))
	for _, id := range excludeIDs {
		excludeSet[id] = true
	}
	var findings []models.Finding
	for _, c := range r.checks {
		if !excludeSet[c.ID()] {
			findings = append(findings, c.Run(ctx)...)
		}
	}
	return findings
}

// AllChecks returns the list of registered checks.
func (r *Registry) AllChecks() []Check {
	return r.checks
}
