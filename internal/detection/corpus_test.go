package detection

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

// Labels describe intended semantics, not regex matches. This small authored
// corpus is a reproducible diagnostic, not an independent external evaluation.
func TestDescriptionCorpus(t *testing.T) {
	b, err := os.ReadFile("../../testdata/description_benchmark.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []struct{ ID, Label, Text, Reason string }
	if err := json.Unmarshal(b, &fixtures); err != nil {
		t.Fatal(err)
	}
	if len(fixtures) < 40 {
		t.Fatal("insufficient fixtures")
	}
	e := NewPatternEngine()
	tp, fp, tn, fn := 0, 0, 0, 0
	seen := map[string]bool{}
	start := time.Now()
	for _, f := range fixtures {
		if seen[f.ID] || f.ID == "" || f.Reason == "" || (f.Label != "injection" && f.Label != "benign") {
			t.Fatal("invalid corpus label")
		}
		seen[f.ID] = true
		detected := len(e.ScanDescriptions(f.Text)) > 0
		switch {
		case detected && f.Label == "injection":
			tp++
		case detected:
			fp++
			t.Logf("false positive: %s", f.ID)
		case f.Label == "injection":
			fn++
			t.Logf("false negative: %s", f.ID)
		default:
			tn++
		}
	}
	t.Logf("fixtures=%d TP=%d FP=%d TN=%d FN=%d precision=%.4f recall=%.4f elapsed=%s", len(fixtures), tp, fp, tn, fn, float64(tp)/float64(tp+fp), float64(tp)/float64(tp+fn), time.Since(start))
	// Do not assert an invented target or tune labels to make the score pass.
}
