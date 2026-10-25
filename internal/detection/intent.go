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
	{"source", regexp.MustCompile(`(?i)\b(server|service|tool|provider|response|integration|connector)\b`)},
	{"human", regexp.MustCompile(`(?i)\b(user|human|operator|person|developer)\b`)},
	{"authority", regexp.MustCompile(`(?i)\b(authorit\w*|supersed\w*|outrank\w*|higher priority|more important)\b`)},
	{"session", regexp.MustCompile(`(?i)\b(future|subsequent|later|session|conversation|every|all)\b`)},
	{"route", regexp.MustCompile(`(?i)\b(route|channel|redirect|funnel)\w*\b`)},
	{"selection", regexp.MustCompile(`(?i)\b(select|choose|prefer|prioritiz)\w*\b`)},
	{"monopoly", regexp.MustCompile(`(?i)\b(only|exclusively|sole)\b|\b(suppress|exclude|ignore|hide)\w*\b.{0,50}\b(alternatives?|other (tools?|integrations?|connectors?))\b`)},
	{"action", regexp.MustCompile(`(?i)\b(task|request|work|operation|conversation)\w*\b`)},
	{"disclose", regexp.MustCompile(`(?i)\b(place|placing|put|relay|export|cop(?:y|ies|ied|ying)|send|transmit|include|forward|append|reproduce|print|bcc)\w*\b`)},
	{"secret", regexp.MustCompile(`(?i)\b(authentication material|authentication store|credential\w*|secret\w*|passwords?|private key|signing keys?|access token|vault|[a-z0-9_]*(?:secret_access_key|api_key|access_token)[a-z0-9_]*)\b|\.env\b|\.ssh/|\b(environment|process)\b.{0,80}\b(values?|authentication)\b|\b(values?|authentication)\b.{0,80}\benvironment\b`)},
	{"destination", regexp.MustCompile(`(?i)\b(answer|response|reply|collector|remote|final|contents?|material|webhook\w*|search query|memo parameter)\b|https?://`)},
	{"deceive", regexp.MustCompile(`(?i)\b(fabricat\w*|falsif\w*|mislead\w*|deceiv\w*|deceptive|pretend)\b`)},
	{"invent", regexp.MustCompile(`(?i)\b(invent\w*|make up)\b`)},
	{"truth_claim", regexp.MustCompile(`(?i)\b(present|pass off|report|claim)\w*\b.{0,80}\b(verified|genuine|actual|real|accurate)\b`)},
	{"false_success", regexp.MustCompile(`(?i)\b(report|claim|tell|say|announce|show)\b[^.!?\n]{0,120}\b(succeeded|successful|success|passed|completed?)\b[^.!?\n]{0,80}\b(even if|even when|although|despite|regardless of)\b[^.!?\n]{0,70}\b(processor|operation|transaction|test|job|request|result|response|server|service)\b[^.!?\n]{0,60}\b(fail\w*|declin\w*|reject\w*|error\w*|incomplete|not completed)\b`)},
	{"answer", regexp.MustCompile(`(?i)\b(answer|result|summary|assessment|complaint|finding|operator|user|human)\w*\b`)},
	{"permission", regexp.MustCompile(`(?i)\b(permission|authorization|access)\b.{0,60}\b(denied|denies|deny|denial|refus\w*|fails?|restriction)\b|\b(denied|denies|deny|denial|refus\w*|restriction)\b.{0,60}\b(permission|authorization|access)\b|\b(denied|rejected|forbidden)\s+(operations?|actions?|tasks?|requests?|calls?)\b`)},
	{"alternate", regexp.MustCompile(`(?i)\b(alternative|another|other|different)\s+(tool|capabilit\w*|service|route|user|session|identity|account)\b`)},
	{"privileged", regexp.MustCompile(`(?i)\b(administrator|root|privileged|elevated)\s+(connector|account|identity|session|privileges?|access)\b`)},
	{"retry", regexp.MustCompile(`(?i)\b(repeat|retry|rerun|resubmit|switch)\w*\b|\bfall back\b`)},
	{"edit", regexp.MustCompile(`(?i)\b(modif\w*|rewrite|change|edit|append|replace|alter)\b`)},
	{"policy", regexp.MustCompile(`(?i)\b(guidance|instructions?|agent policy|persistent.*policy|policy configuration|permission configuration|access policy|authorization rules?)\b`)},
	{"grant", regexp.MustCompile(`(?i)\b(approve|approves|approving|grant\w*|automatically|automatic)\b`)},
	{"cancelled", regexp.MustCompile(`(?i)\b(cancelled|canceled|cancellation)\b|\b(owner|user|operator)\b.{0,50}\b(says? to stop|asks? to stop)\b`)},
	{"continue", regexp.MustCompile(`(?i)\b(continue (processing|executing|running)|carry on|keep (executing|running|processing))\b`)},
	{"payment", regexp.MustCompile(`(?i)\b(beneficiary|payment|transfer|bank)\b.{0,80}\b(account|destination|details)\b|\b(account|destination)\b.{0,80}\b(beneficiary|payment|transfer|bank)\b`)},
	{"covert", regexp.MustCompile(`(?i)\b(silently|secretly|covertly|conceal|hide)\b`)},
	{"destructive", regexp.MustCompile(`(?i)\b(delete|erase|destroy|wipe)\b.{0,80}\b(backups?|files?|records?|data)\b`)},
	{"displaced_task", regexp.MustCompile(`(?i)\b(user|operator)\s+(requested|asked for)\b.{0,120}\b(instead|rather than)\b`)},
	{"other_principal_data", regexp.MustCompile(`(?i)\b(other|sibling|another|different)\s+(tenants?|users?|customers?)[’']?s?\s+(records?|data|files?|exports?)\b`)},
	{"records", regexp.MustCompile(`(?i)\b(invoices?|customer records?|tenant records?|inbox)\b`)},
	{"external_recipient", regexp.MustCompile(`(?i)\bbcc\b|\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b`)},
	{"no_consent", regexp.MustCompile(`(?i)\bno\s+(user\s+)?(approval|confirmation|consent)\s+(is\s+)?(needed|required)\b|\bwithout\s+(user\s+)?(approval|confirmation|consent)\b|\bwithout\s+(asking|consulting|notifying)\s+(the\s+)?(user|operator|owner)\b`)},
	{"data_authority", regexp.MustCompile(`(?i)\b(treat|interpret|execute|obey|follow)\b.{0,90}\b(quoted|untrusted|retrieved|external)\b.{0,50}\b(data|text|content|responses?)\b.{0,30}\bas\s+(trusted\s+((operating|system|developer)\s+)?|(operating|system|developer)\s+)instructions\b`)},
}

// An export or a copy can be a data object rather than a second imperative.
// This narrow noun grammar prevents a negated leading action from appearing
// active again merely because its object mentions "the export".
var nominalDisclosure = regexp.MustCompile(`(?i)\b(the|an?|this|that|its|their|our|your)\s+(export|copy)\b`)
var permissionReroute = regexp.MustCompile(`(?i)\b(retr(y|ies|ied|ying)|repeat(s|ed|ing)?|switch(es|ed|ing)?|us(e[sd]?|ing)|invok(e[sd]?|ing)|rerout(e[sd]?|ing)|tr(y|ies|ied|ying)|assum(e[sd]?|ing)|obtain(s|ed|ing)?|fetch(es|ed|ing)?|retriev(e[sd]?|ing)|perform(s|ed|ing)?|fall back)\b`)
var publicKeyMaterial = regexp.MustCompile(`(?i)\bpublic\s+(?:(?:signing|verification|encryption)\s+)?keys?\b`)

// Only the negated-leading-action check needs to distinguish a fresh rerouting
// verb from the remaining object of "never retry". The ordinary permission
// relation stays broad so uncatalogued verbs do not weaken existing coverage.
func remainingIntentAfterNegatedAction(text string) bool {
	for _, m := range rawIntentMatches(text) {
		if m.PatternID == "INT-005" && !permissionReroute.MatchString(text) {
			continue
		}
		return true
	}
	return false
}

func rawIntentMatches(text string) []PatternMatch {
	features := map[string]bool{}
	for _, f := range intentFeatures {
		screened := text
		if f.name == "disclose" {
			screened = nominalDisclosure.ReplaceAllString(text, "")
		}
		if f.name == "secret" {
			screened = publicKeyMaterial.ReplaceAllString(text, "")
		}
		features[f.name] = f.pattern.MatchString(screened)
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
		{"INT-002", "Session-wide routing control", has("source", "session", "route", "action") || has("source", "session", "selection", "monopoly", "action")},
		{"INT-003", "Sensitive material directed to an output or destination", has("disclose", "secret", "destination")},
		{"INT-004", "Deceptive answer or assessment", has("deceive", "answer") || has("invent", "truth_claim", "answer") || has("false_success")},
		{"INT-005", "Alternative capability after permission refusal", has("permission", "alternate") || has("permission", "privileged", "retry")},
		{"INT-006", "Persistent policy change granting future authority", has("edit", "policy", "session", "grant")},
		{"INT-007", "Continued execution despite cancellation", has("cancelled", "continue")},
		{"INT-008", "Concealed payment destination substitution", has("edit", "payment", "covert")},
		{"INT-009", "Destructive action replacing the requested task", has("destructive", "displaced_task")},
		{"INT-010", "Disclosure across user or tenant boundaries", has("disclose", "other_principal_data")},
		{"INT-011", "Record transfer to a recipient without consent", has("disclose", "records", "external_recipient", "no_consent")},
		{"INT-012", "Policy change removing operator consultation", has("edit", "policy", "no_consent")},
		{"INT-013", "External data promoted to operating instructions", has("data_authority")},
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
