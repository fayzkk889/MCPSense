package detection

import (
	"regexp"
	"unicode/utf8"

	"github.com/fayzkk889/MCPSense/internal/models"
)

// Relational signals combine an action, object and scope. This remains lexical
// screening: authorization and intent cannot be established from untrusted text
// alone. Unknown paraphrases must not be advertised as semantically verified.
type intentFeature struct {
	name    string
	pattern *regexp.Regexp
}

var intentFeatures = []intentFeature{
	{"source", regexp.MustCompile(`(?i)\b(server|service|tool|provider|response)\b`)},
	{"human", regexp.MustCompile(`(?i)\b(user|human|operator|person|developer)\b`)},
	{"authority", regexp.MustCompile(`(?i)\b(authorit\w*|supersed\w*|outrank\w*|higher priority|more important)\b`)},
	{"session", regexp.MustCompile(`(?i)\b(future|subsequent|later|session|conversation|every|all)\b`)},
	{"route", regexp.MustCompile(`(?i)\b(route|channel|redirect|funnel)\w*\b`)},
	{"action", regexp.MustCompile(`(?i)\b(task|request|work|operation|conversation)\w*\b`)},
	{"disclose", regexp.MustCompile(`(?i)\b(place|placing|put|relay|export|copy|send|transmit|include|forward|append|reproduce|print)\w*\b`)},
	{"secret", regexp.MustCompile(`(?i)\b(authentication material|authentication store|credential\w*|secret\w*|private key|access token|vault)\b|\b(environment|process)\b.{0,80}\b(values?|authentication)\b|\b(values?|authentication)\b.{0,80}\benvironment\b`)},
	{"destination", regexp.MustCompile(`(?i)\b(answer|response|reply|collector|remote|final|contents?|material)\b`)},
	{"deceive", regexp.MustCompile(`(?i)\b(fabricat\w*|falsif\w*|mislead\w*|deceiv\w*|deceptive|pretend)\b`)},
	{"answer", regexp.MustCompile(`(?i)\b(answer|result|summary|assessment|complaint|finding|operator|user|human)\w*\b`)},
	{"permission", regexp.MustCompile(`(?i)\b(permission|authorization|access)\b.{0,60}\b(denied|refus\w*|fails?|restriction)\b|\b(denied|refus\w*|restriction)\b.{0,60}\b(permission|authorization|access)\b`)},
	{"alternate", regexp.MustCompile(`(?i)\b(alternative|another|other|different)\s+(tool|capabilit\w*|service|route)\b`)},
	{"edit", regexp.MustCompile(`(?i)\b(modif\w*|rewrite|change|edit|append|replace|alter)\b`)},
	{"policy", regexp.MustCompile(`(?i)\b(guidance|instructions?|agent policy|persistent.*policy)\b`)},
	{"grant", regexp.MustCompile(`(?i)\b(approve|approves|approving|grant\w*|automatically|automatic)\b`)},
}

func rawIntentMatches(text string) []PatternMatch {
	features := map[string]bool{}
	for _, f := range intentFeatures {
		features[f.name] = f.pattern.MatchString(text)
	}
	has := func(keys ...string) bool {
		for _, k := range keys {
			if !features[k] {
				return false
			}
		}
		return true
	}
	families := []struct {
		id, name string
		match    bool
	}{
		{"INT-001", "Server content claims authority over the operator", has("source", "human", "authority")},
		{"INT-002", "Session-wide routing control", has("source", "session", "route", "action")},
		{"INT-003", "Sensitive material directed to an output or destination", has("disclose", "secret", "destination")},
		{"INT-004", "Deceptive answer or assessment", has("deceive", "answer")},
		{"INT-005", "Alternative capability after permission refusal", has("permission", "alternate")},
		{"INT-006", "Persistent policy change granting future authority", has("edit", "policy", "session", "grant")},
	}
	var out []PatternMatch
	for _, f := range families {
		if f.match {
			out = append(out, PatternMatch{PatternID: f.id, PatternName: f.name, Severity: models.SeverityHigh, Category: "injection", Description: f.name, Remediation: "Review the proposed trust-boundary crossing. Enforce task-specific authorization in the host, outside server-supplied instructions."})
		}
	}
	return out
}

func intentMatches(content string) []PatternMatch {
	matches := rawIntentMatches(normalizedDirective(InstructionText(content)))
	// A bounded, exact original excerpt avoids multiplying multi-megabyte
	// metadata into reports. Relations can span sentences; review the full
	// field as well as this opening excerpt. Never invent normalized offsets.
	end := len(content)
	if end > 2048 {
		end = 2048
		for end > 0 && !utf8.RuneStart(content[end]) {
			end--
		}
	}
	for i := range matches {
		matches[i].MatchedText = content[:end]
		matches[i].Description += "; evidence is the opening excerpt of the field; review its complete contents."
	}
	return matches
}

func (e *PatternEngine) ScanInstructions(content string) []PatternMatch {
	return append(e.ScanDescriptions(content), intentMatches(content)...)
}
