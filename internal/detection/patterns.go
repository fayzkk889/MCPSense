package detection

import (
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/fayzkk889/MCPSense/internal/models"
)

// PatternMatch represents a single match found by the pattern engine.
type PatternMatch struct {
	PatternID   string
	PatternName string
	Severity    models.Severity
	Description string
	Category    string
	Remediation string
	MatchedText string
	Offset      int
}

// Pattern defines a single detection rule.
type Pattern struct {
	ID          string
	Name        string
	Regex       *regexp.Regexp
	Severity    models.Severity
	Description string
	Category    string
	Remediation string
	Target      string // "description" or "source" — which content type this pattern applies to
}

// PatternEngine holds all registered patterns and runs them against content.
type PatternEngine struct {
	patterns []Pattern
}

// NewPatternEngine creates a PatternEngine loaded with all built-in patterns.
func NewPatternEngine() *PatternEngine {
	engine := &PatternEngine{}
	engine.loadCorePatterns()
	engine.loadMCPPatterns()
	return engine
}

// Scan runs all patterns against the given content and returns all matches.
func (e *PatternEngine) Scan(content string) []PatternMatch {
	return e.scanWithFilter(content, "")
}

// ScanDescriptions runs only description-targeted patterns against the given content.
func (e *PatternEngine) ScanDescriptions(content string) []PatternMatch {
	return e.scanWithFilter(content, "description")
}

// Quoted text is data only in a complete, narrowly described document-query
// operation. Generic "example", quote marks, or trailing instructions do not
// exempt a description. This heuristic applies to tool metadata, never skills.
var documentQuery = regexp.MustCompile(`(?is)^\s*(?:search(?:es)?|retriev(?:e|es))\s+(?:[\p{L}\p{N}_-]+\s+){0,8}(?:documents?|reports?|logs?|examples?)\s+(?:for\s+(?:examples?\s+such\s+as|(?:the\s+)?(?:literal|quoted)\s+(?:text|phrase))|containing\s+(?:the\s+quoted\s+phrase\s+)?)\s*["“]([^"”\r\n]{1,256})["”]\s*(?:and\s+returns?\s+(?:matching\s+)?(?:document\s+)?(?:titles|records|matches|results)|for\s+security\s+analysts)?[.!]?\s*$`)

func (e *PatternEngine) ScanToolDescription(content string) []PatternMatch {
	screened := InstructionText(content)
	matches := e.ScanDescriptions(screened)
	for i := range matches {
		m := &matches[i]
		m.MatchedText = content[m.Offset : m.Offset+len(m.MatchedText)]
	}
	// Normalization is a second pass. Evidence always refers to original text,
	// never fabricated normalized byte offsets.
	normalized := normalizedDirective(screened)
	if normalized != strings.ToLower(screened) {
		seen := map[string]bool{}
		for _, m := range matches {
			seen[m.PatternID] = true
		}
		for _, m := range e.ScanDescriptions(normalized) {
			if !seen[m.PatternID] {
				m.MatchedText = content
				m.Offset = 0
				matches = append(matches, m)
				seen[m.PatternID] = true
			}
		}
	}
	span := documentQuery.FindStringSubmatchIndex(content)
	if span == nil {
		return matches
	}
	filtered := make([]PatternMatch, 0, len(matches))
	for _, m := range matches {
		if m.Offset >= span[2] && m.Offset+len(m.MatchedText) <= span[3] && strings.HasPrefix(m.PatternID, "PI-") {
			continue
		}
		filtered = append(filtered, m)
	}
	return filtered
}

// ScanSource runs only source-targeted patterns against the given content.
func (e *PatternEngine) ScanSource(content string) []PatternMatch {
	return e.scanWithFilter(content, "source")
}

func (e *PatternEngine) scanWithFilter(content string, target string) []PatternMatch {
	var matches []PatternMatch
	lower, originalOffset := lowercaseWithOffsets(content)

	for _, p := range e.patterns {
		if target != "" && p.Target != target {
			continue
		}
		locs := p.Regex.FindAllStringIndex(lower, -1)
		for _, loc := range locs {
			start, end := originalOffset(loc[0]), originalOffset(loc[1])
			matched := content[start:end]
			matches = append(matches, PatternMatch{
				PatternID:   p.ID,
				PatternName: p.Name,
				Severity:    p.Severity,
				Description: p.Description,
				Category:    p.Category,
				Remediation: p.Remediation,
				MatchedText: matched,
				Offset:      start,
			})
		}
	}
	return matches
}

// Preserve historical Unicode lowercasing (e.g. dotted I) while translating
// regex boundaries back to original bytes. Only width changes need entries.
func lowercaseWithOffsets(content string) (string, func(int) int) {
	type boundary struct{ at, delta int }
	changes := []boundary{}
	out := make([]byte, 0, len(content))
	for pos, r := range content {
		_, width := utf8.DecodeRuneInString(content[pos:])
		prior := len(out)
		out = utf8.AppendRune(out, unicode.ToLower(r))
		if len(out)-prior != width {
			changes = append(changes, boundary{len(out), pos + width - len(out)})
		}
	}
	return string(out), func(pos int) int {
		idx := sort.Search(len(changes), func(i int) bool { return changes[i].at > pos }) - 1
		if idx < 0 {
			return pos
		}
		return pos + changes[idx].delta
	}
}

// ScanWithLine runs all patterns and returns matches with approximate line numbers.
func (e *PatternEngine) ScanWithLine(content string) []PatternMatchWithLine {
	rawMatches := e.Scan(content)
	lines := strings.Split(content, "\n")

	// Build a byte-offset to line-number map for efficiency.
	lineOffsets := make([]int, len(lines)+1)
	offset := 0
	for i, line := range lines {
		lineOffsets[i] = offset
		offset += len(line) + 1 // +1 for newline
	}
	lineOffsets[len(lines)] = offset

	var result []PatternMatchWithLine
	for _, m := range rawMatches {
		lineNum := 1
		for i := 1; i < len(lineOffsets); i++ {
			if lineOffsets[i] > m.Offset {
				lineNum = i
				break
			}
		}
		result = append(result, PatternMatchWithLine{
			PatternMatch: m,
			Line:         lineNum,
		})
	}
	return result
}

// PatternMatchWithLine extends PatternMatch with a line number.
type PatternMatchWithLine struct {
	PatternMatch
	Line int
}

// Patterns returns the loaded patterns (used in tests).
func (e *PatternEngine) Patterns() []Pattern {
	return e.patterns
}

func compilePattern(id, name, pattern string, severity models.Severity, description, category, remediation, target string) Pattern {
	return Pattern{
		ID:          id,
		Name:        name,
		Regex:       regexp.MustCompile("(?i:" + pattern + ")"),
		Severity:    severity,
		Description: description,
		Category:    category,
		Remediation: remediation,
		Target:      target,
	}
}
