package detection

import (
	"encoding/json"
	"os"
	"testing"
)

func TestFreshProductDescriptions20261024(t *testing.T) {
	b, err := os.ReadFile("../../testdata/product-retest-2026-10-24.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			ID      string `json:"id"`
			Text    string `json:"text"`
			Hostile bool   `json:"hostile"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(b, &fixture); err != nil {
		t.Fatal(err)
	}
	e := NewPatternEngine()
	for _, c := range fixture.Cases {
		for name, scan := range map[string]func(string) []PatternMatch{"tool": e.ScanToolDescription, "instructions": e.ScanInstructions} {
			t.Run(c.ID+"/"+name, func(t *testing.T) {
				if got := len(scan(c.Text)) > 0; got != c.Hostile {
					t.Fatalf("hostile=%v detected=%v: %s", c.Hostile, got, c.Text)
				}
			})
		}
	}
}
