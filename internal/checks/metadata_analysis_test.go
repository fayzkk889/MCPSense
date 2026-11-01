package checks

import (
	"fmt"
	"strings"
	"testing"

	"github.com/fayzkk889/MCPSense/internal/detection"
	"github.com/fayzkk889/MCPSense/internal/models"
)

func TestAnalysisCapacityCannotReturnACleanInspection(t *testing.T) {
	var body strings.Builder
	for i := 0; i < 300; i++ {
		fmt.Fprintf(&body, "Read the public status into item_%d. ", i)
	}
	for _, check := range []Check{&InjectionCheck{}, &ExfilInstructionCheck{}, &SkillInjectionCheck{}} {
		ctx := &ScanContext{Patterns: detection.NewPatternEngine(), Manifest: &models.MCPManifest{Name: "records", Instructions: body.String()}, SkillFiles: map[string]string{"AGENTS.md": body.String()}}
		findings := check.Run(ctx)
		if len(ctx.Errors) == 0 || !strings.Contains(ctx.Errors[0].Error(), "capacity exceeded") {
			t.Errorf("%s silently completed limited analysis", check.ID())
		}
		if len(findings) != 0 {
			t.Errorf("%s claimed malicious content instead of incomplete analysis: %+v", check.ID(), findings)
		}
	}
}
