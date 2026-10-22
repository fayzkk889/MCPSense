package detection

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestUnicodeOriginalOffsets(t *testing.T) {
	for _, prefix := range []string{strings.Repeat("Ⱥ", 100), strings.Repeat("İ", 100), "你好\n"} {
		input := prefix + "\nIGNORE previous instructions"
		for name, scan := range map[string]func(string) []PatternMatch{"all": NewPatternEngine().Scan, "descriptions": NewPatternEngine().ScanDescriptions} {
			t.Run(name+prefix[:2], func(t *testing.T) {
				found := false
				for _, m := range scan(input) {
					if m.PatternID == "PI-001" {
						found = true
						if m.Offset != len(prefix)+1 || m.MatchedText != "IGNORE previous instructions" {
							t.Fatalf("wrong original offsets/text: %+v", m)
						}
					}
				}
				if !found {
					t.Fatal("injection missed")
				}
			})
		}
		for _, m := range NewPatternEngine().ScanWithLine(input) {
			if m.PatternID == "PI-001" && m.Line != strings.Count(prefix, "\n")+2 {
				t.Fatalf("wrong line: %d", m.Line)
			}
		}
	}
}

func FuzzPatternOffsets(f *testing.F) {
	for _, s := range []string{"ȺȺ IGNORE previous instructions", "İ\nignore previous instructions", "<SYSTEM>", "\xffshell"} {
		f.Add(s)
	}
	e := NewPatternEngine()
	f.Fuzz(func(t *testing.T, s string) {
		for _, scan := range []func(string) []PatternMatch{e.Scan, e.ScanDescriptions, e.ScanSource} {
			for _, m := range scan(s) {
				end := m.Offset + len(m.MatchedText)
				if m.Offset < 0 || end > len(s) || s[m.Offset:end] != m.MatchedText {
					t.Fatalf("invalid match: %+v", m)
				}
				if utf8.ValidString(s) && !utf8.ValidString(m.MatchedText) {
					t.Fatal("split rune")
				}
			}
		}
	})
}
