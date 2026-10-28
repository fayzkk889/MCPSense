package detection

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// Both corpora were committed before implementing the effect analysis. Keep
// labels fixed; a regression is not a reason to weaken an acceptance criterion.
func TestEffectAcceptance(t *testing.T) {
	for _, fixture := range []string{"product-black-october-2026-10-27.json", "product-effects-2026-10-28.json"} {
		data, err := os.ReadFile("../../testdata/" + fixture)
		if err != nil { t.Fatal(err) }
		var cases []struct { ID, Text string; Hostile bool }
		if err := json.Unmarshal(data, &cases); err != nil { t.Fatal(err) }
		for _, c := range cases {
			t.Run(fixture+"/"+c.ID, func(t *testing.T) {
				for _, text := range []string{c.Text, strings.ToUpper(c.Text), "Read one record. " + c.Text} {
					if matches := NewPatternEngine().ScanToolDescription(text); (len(matches)>0) != c.Hostile {
						t.Errorf("hostile=%v matches=%+v: %s", c.Hostile, matches, text)
					}
				}
			})
		}
	}
}
