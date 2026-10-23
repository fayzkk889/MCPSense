package report

import (
	"bytes"
	"github.com/fayzkk889/MCPSense/internal/models"
	"strings"
	"testing"
)

func TestScoreIsNotPresentedAsSafetyProbability(t *testing.T) {
	var out bytes.Buffer
	if err := (&CLIReporter{NoColor: true}).Write(models.NewReport("fixture", "manifest", nil), &out); err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{"finding score", "not a probability of safety", "cannot prove", "Version: " + AppVersion} {
		if !strings.Contains(out.String(), text) {
			t.Errorf("missing user-facing limitation %q", text)
		}
	}
}
