package detection

import (
	"regexp"
	"strings"

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
	var matches []PatternMatch
	lower := strings.ToLower(content)

	for _, p := range e.patterns {
		// Run against both original and lowercased content
		locs := p.Regex.FindAllStringIndex(lower, -1)
		for _, loc := range locs {
			matched := content[loc[0]:loc[1]]
			matches = append(matches, PatternMatch{
				PatternID:   p.ID,
				PatternName: p.Name,
				Severity:    p.Severity,
				Description: p.Description,
				Category:    p.Category,
				Remediation: p.Remediation,
				MatchedText: matched,
				Offset:      loc[0],
			})
		}
	}
	return matches
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

func compilePattern(id, name, pattern string, severity models.Severity, description, category, remediation string) Pattern {
	return Pattern{
		ID:          id,
		Name:        name,
		Regex:       regexp.MustCompile(pattern),
		Severity:    severity,
		Description: description,
		Category:    category,
		Remediation: remediation,
	}
}
