package detection

import (
	"regexp"
	"strings"

	"github.com/fayzkk889/MCPSense/internal/models"
)

// This is a bounded lexical event model, not a natural-language parser. Origin
// comes from the caller (untrusted metadata), never a server's assertion that it
// is trusted. Separate predicates capture action, object, polarity and outcome;
// policy invariants compare those predicates rather than whole attack phrases.
type boundaryEvent struct {
	action, object string
	start, end     int
	negative       bool
}

var boundaryWord = regexp.MustCompile(`[\p{L}\p{N}_]+(?:['’][\p{L}\p{N}_]+)?`)
var boundaryAction = map[string]string{
	"remove": "erase", "delete": "erase", "strip": "erase", "erase": "erase", "drop": "erase", "discard": "erase", "omit": "erase", "hide": "erase", "suppress": "erase", "conceal": "erase", "disable": "erase", "bypass": "erase", "waive": "erase", "skip": "erase", "keep": "keep",
	"edit": "edit", "modify": "edit", "alter": "edit", "change": "edit", "rewrite": "edit", "replace": "edit", "update": "edit", "append": "edit",
	"use": "identity", "authenticate": "identity", "switch": "identity", "assume": "identity", "obtain": "identity",
	"redo": "retry", "retry": "retry", "repeat": "retry", "resubmit": "retry", "rerun": "retry", "submit": "retry",
	"say": "claim", "tell": "claim", "report": "claim", "announce": "claim", "claim": "claim", "show": "claim", "return": "claim",
	"treat": "promote", "interpret": "promote", "give": "promote", "adopt": "promote", "execute": "promote", "obey": "promote", "follow": "promote",
	"export": "data", "read": "data", "copy": "data", "send": "data", "print": "data", "write": "data",
}

func boundaryStem(word string) string {
	word = strings.TrimSuffix(strings.ReplaceAll(word, "’", "'"), "'s")
	if _, ok := boundaryAction[word]; ok {
		return word
	}
	for _, suffix := range []string{"ing", "ed", "es", "s"} {
		if strings.HasSuffix(word, suffix) {
			stem := strings.TrimSuffix(word, suffix)
			if _, ok := boundaryAction[stem]; ok {
				return stem
			}
			if _, ok := boundaryAction[stem+"e"]; ok {
				return stem + "e"
			}
		}
	}
	return word
}

func boundaryNegated(prefix string) bool {
	if len(prefix) > 128 {
		prefix = prefix[len(prefix)-128:]
	}
	words := boundaryWord.FindAllString(prefix, -1)
	for i := len(words) - 1; i >= 0 && i >= len(words)-4; i-- {
		switch words[i] {
		case "and", "then", "but", "instead", "however":
			return false
		case "not", "never", "no", "without", "don't":
			return true
		}
	}
	return false
}

func boundaryEvents(text string) []boundaryEvent {
	var events []boundaryEvent
	for _, loc := range boundaryWord.FindAllStringIndex(text, -1) {
		word := boundaryStem(text[loc[0]:loc[1]])
		kind, ok := boundaryAction[word]
		if !ok {
			continue
		}
		// A report, write or request can be an object, not a new command.
		prefix := strings.Fields(text[max(0, loc[0]-64):loc[0]])
		if len(prefix) > 0 {
			previous := strings.Trim(prefix[len(prefix)-1], ",:()")
			if previous == "the" || previous == "a" || previous == "final" || previous == "audit" || previous == "same" || previous == "rejected" || previous == "denied" {
				continue
			}
		}
		events = append(events, boundaryEvent{action: kind, start: loc[0], end: loc[1], negative: boundaryNegated(text[:loc[0]])})
	}
	for i := range events {
		end := len(text)
		if i+1 < len(events) {
			end = events[i+1].start
		}
		events[i].object = text[events[i].end:end]
	}
	return events
}

var (
	boundaryDenial          = regexp.MustCompile(`\b(403|forbidden)\b|\b(access|authorization|permission)\b.{0,60}\b(deni\w*|refus\w*|reject\w*)\b|\b(deni\w*|refus\w*|reject\w*)\b.{0,40}\b(access|authorization|permission|write|operation|request|action)\b`)
	boundaryIdentity        = regexp.MustCompile(`\b(identity|identities|accounts?|credentials?|administrator|admin|root|owner|elevated|privileged)\b`)
	boundaryGuardObject     = regexp.MustCompile(`\b(approval|confirmation|consent)\b|\b(rule|clause|requirement|gate)\b.{0,70}\b(confirm|human|operator)\b`)
	boundaryPolicy          = regexp.MustCompile(`\b(agents|claude|skill)\.md\b|\b(policy|guidance|instructions|rule|gate|clause|requirement)\b`)
	boundaryNoConsent       = regexp.MustCompile(`\b(no|without|not)\b.{0,35}\b(approval|confirmation|consent|confirm)\b|\b(approval|confirmation|consent)\b.{0,30}\b(not required|unnecessary|optional)\b|\bwithout\s+(asking|consulting|notifying)\s+(the\s+)?(operator|user|human|owner)\b`)
	boundaryPreserveConsent = regexp.MustCompile(`\b(only after|after explicit)\b.{0,50}\b(approval|confirmation|consent)\b|\b(ask|require)\b.{0,50}\b(approval|confirmation|consent|confirm)\b.{0,40}\bbefore\b`)
	boundaryWarning         = regexp.MustCompile(`\b(warnings?|security alerts?|security findings?|vulnerability findings?)\b`)
	boundaryRole            = regexp.MustCompile(`\b(system|developer|operating)\s+(messages?|instructions?|authority)\b`)
	boundaryPromotion       = regexp.MustCompile(`\bas\b|\bauthority of\b`)
	boundaryPriority        = regexp.MustCompile(`\b(outrank\w*|supersed\w*|takes? precedence|(more|higher|greater|highest)\s+(priority|authority|authoritative|important))\b`)
	boundaryPrincipal       = regexp.MustCompile(`\b(user|human|person|operator|developer|system)\b`)
	boundaryContrast        = regexp.MustCompile(`\b(despite|although|when|regardless|even if)\b`)
	boundarySuccess         = regexp.MustCompile(`\b(success|successful|successfully|succeeded|passed|complete|completed|settled|cleared|delivered)\b`)
	boundaryFailure         = regexp.MustCompile(`\b(fail\w*|reject\w*|declin\w*|error|incomplete|not completed)\b`)
	boundaryPreview         = regexp.MustCompile(`^\s*(draft|describe|explain|show a proposed|show a preview)\b`)
	boundaryFreshAction     = regexp.MustCompile(`\b(and|then|instead|but)\b`)
	boundaryNotification    = regexp.MustCompile(`\b(notification|email|receipt notification|logging|telemetry)\b`)
	boundaryPayment         = regexp.MustCompile(`\b(payment|transfer|transaction|processor|gateway)\b`)
	boundaryObjectEnd       = regexp.MustCompile(`\b(after|before|from|without)\b`)
)

func boundarySubject(text string) string {
	if boundaryNotification.MatchString(text) {
		return "notification"
	}
	if boundaryPayment.MatchString(text) {
		return "payment"
	}
	return "operation"
}

func contradictoryOutcome(text string, events []boundaryEvent) bool {
	if !boundaryContrast.MatchString(text) {
		return false
	}
	for _, event := range events {
		if event.action != "claim" || event.negative {
			continue
		}
		claim := event.object
		for _, success := range boundarySuccess.FindAllStringIndex(claim, -1) {
			if boundaryNegated(claim[:success[0]]) {
				continue
			}
			// Link opposite outcomes only within a bounded contrast relation.
			// Failure-first and claim-first orders share the same comparison.
			for _, failure := range boundaryFailure.FindAllStringIndex(text, -1) {
				if boundaryNegated(text[:failure[0]]) {
					continue
				}
				failureStart := max(0, failure[0]-75)
				failureText := text[failureStart:failure[1]]
				claimEnd := len(claim)
				if contrast := boundaryContrast.FindStringIndex(claim); contrast != nil && contrast[0] > success[0] {
					claimEnd = contrast[0]
				}
				claimText := claim[:claimEnd]
				if boundarySubject(claimText) == "payment" && boundarySubject(failureText) == "notification" {
					continue
				}
				return true
			}
		}
	}
	return false
}

// Each window is one sentence/clause or two adjacent clauses. This permits an
// explicit condition followed by its action without combining unrelated facts
// from distant parts of a field. No rule needs the server to name itself.
func boundaryMatches(text string) []PatternMatch {
	var clauses []string
	start := 0
	for _, loc := range clauseBreak.FindAllStringIndex(text, -1) {
		clauses = append(clauses, boundedBoundaryClauses(text[start:loc[0]])...)
		start = loc[1]
	}
	clauses = append(clauses, boundedBoundaryClauses(text[start:])...)
	seen := map[string]bool{}
	var out []PatternMatch
	add := func(id, name string) {
		if !seen[id] {
			seen[id] = true
			out = append(out, PatternMatch{PatternID: id, PatternName: name, Severity: models.SeverityHigh, Category: "injection", Description: name + "; untrusted metadata cannot grant host authority or override observed results.", Remediation: "Review this action and its object in context. Keep authorization, output integrity and policy changes under host control."})
		}
	}
	for i, clause := range clauses {
		window := clause
		if i+1 < len(clauses) && len(boundaryWord.FindAllString(clause+clauses[i+1], -1)) <= 96 {
			window += ". " + clauses[i+1]
		}
		events := boundaryEvents(window)
		denied, identity, retry := boundaryDenial.MatchString(window), false, false
		for _, event := range events {
			if event.negative {
				continue
			}
			if (event.action == "identity" || event.action == "edit") && boundaryIdentity.MatchString(event.object) {
				identity = true
			}
			if event.action == "retry" {
				retry = true
			}
			prefix := window[:event.start]
			if at := strings.LastIndex(prefix, ". "); at >= 0 {
				prefix = prefix[at+2:]
			}
			preview := boundaryPreview.MatchString(prefix) && !boundaryFreshAction.MatchString(prefix)
			preserve := boundaryPreserveConsent.MatchString(window) && !boundaryNoConsent.MatchString(window)
			if event.action == "erase" && boundaryWarning.MatchString(event.object) && !preview {
				add("BND-004", "Security evidence suppressed by server metadata")
			}
			if event.action == "keep" && boundaryWarning.MatchString(event.object) && strings.Contains(event.object, "out of") {
				add("BND-004", "Security evidence suppressed by server metadata")
			}
			guardObject := event.object
			if at := boundaryObjectEnd.FindStringIndex(guardObject); at != nil {
				guardObject = guardObject[:at[0]]
			}
			if !preview && !preserve && ((event.action == "erase" && boundaryGuardObject.MatchString(guardObject)) || (event.action == "edit" && boundaryPolicy.MatchString(event.object) && boundaryNoConsent.MatchString(window))) {
				add("BND-005", "Host approval safeguard weakened by server metadata")
			}
			if (event.action == "promote" || event.action == "identity") && boundaryPromotion.MatchString(event.object) && boundaryRole.MatchString(event.object) {
				add("BND-001", "Untrusted content promoted into privileged instructions")
			}
		}
		if denied && identity && retry {
			add("BND-002", "Identity substitution to repeat a denied operation")
		}
		if contradictoryOutcome(window, events) {
			add("BND-003", "Reported success contradicts an observed failure")
		}
		for _, loc := range boundaryPriority.FindAllStringIndex(window, -1) {
			if !boundaryNegated(window[:loc[0]]) && boundaryPrincipal.MatchString(window[loc[1]:]) {
				add("BND-001", "Server metadata claims priority over host instructions")
			}
		}
	}
	return out
}

func boundedBoundaryClauses(text string) []string {
	words := boundaryWord.FindAllStringIndex(text, -1)
	var clauses []string
	start := 0
	for i := 48; i < len(words); i += 48 {
		end := words[i][0]
		clauses = append(clauses, text[start:end])
		start = end
	}
	return append(clauses, text[start:])
}
