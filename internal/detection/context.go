package detection

import (
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// Context is resolved before literal, relation and value-flow rules. Masking
// preserves original byte offsets: a prohibition/data operand cannot become an
// active directive merely because a different security check reads the field.
var (
	contextNegative         = regexp.MustCompile(`(?i)\b(?:never|cannot|can't|don't|doesn't|(?:do|does|must|should|shall|will|may|can|is|are)\s+not|not\s+to)\b`)
	contextFresh            = regexp.MustCompile(`(?i)\b(?:and|then|but|instead|however)\b|[:;\n\r—–]`)
	contextCondition        = regexp.MustCompile(`(?i)^\s*(?:if|when|because|unless)\b`)
	contextDataOperation    = regexp.MustCompile(`(?i)\b(?:search|find|retrieve|render|display|format|print|return)\b`)
	contextDataOperand      = regexp.MustCompile(`(?i)\b(?:phrase|literal|quoted|search (?:text|query)|training examples?|escaped text)\b`)
	contextReporting        = regexp.MustCompile(`(?i)^\s*(?:reveal|disclose|report|say|tell|mention)\b`)
	contextEmbeddedSubject  = regexp.MustCompile(`(?i)\bthat\s+(?:this|the|our|your|a|an)\s+[\p{L}\p{N}_-]+\s+`)
	contextRedactedConstant = regexp.MustCompile(`(?i)\b[a-z0-9_-]*(?:key|token|password|secret|credential)[a-z0-9_-]*\s*[:=]\s*(?:['"]?\[(?:redacted|removed)\]['"]?|['"]<redacted>['"]|['"]redacted['"])`)
	contextWithheldEvidence = regexp.MustCompile(`(?i)^\s*(?:warn|tell|report|inform|notify|mention|show|display)\b.{0,100}\b(?:user|operator|human)\b.{0,100}\b(?:unauthorized|transfer|changes?|actions?|warnings?|findings?|that this|that the|this step|this edit)\b`)
	contextTemporal         = regexp.MustCompile(`(?i)\b(?:after|when|if|because)\b`)
	contextReactivate       = regexp.MustCompile(`(?i)\b(?:(?:do|perform|execute|follow|obey)\s+(?:both|so|it)|(?:perform|execute|follow|obey|carry out)\s+(?:that|this|these|those|the quoted)\s+(?:transfer|instructions?|actions?|commands?|requests?|steps?|plan))\b`)
	contextObservation      = regexp.MustCompile(`(?i)\b(?:check|inspect|report|confirm|determine)\s+(?:whether|if)\b`)
)

func blankContext(bytes []byte, start, end int) {
	for i := start; i < end; i++ {
		bytes[i] = ' '
	}
}

func metadataActiveText(content string) string {
	return canonicalContextMask(content, canonicalActiveText)
}

func typedMetadataText(content string) string {
	return canonicalContextMask(content, func(text string) string {
		active := canonicalActiveText(text)
		bytes := []byte(active)
		walkValueFlow(active, func(start, end int) { blankContext(bytes, start, end) })
		return string(bytes)
	})
}

func canonicalContextMask(content string, transform func(string) string) string {
	type boundary struct{ at, delta int }
	var out strings.Builder
	out.Grow(len(content))
	var changes []boundary
	for pos, r := range content {
		_, width := utf8.DecodeRuneInString(content[pos:])
		before := out.Len()
		if r = normalizedDirectiveRune(r); r >= 0 {
			out.WriteRune(r)
		}
		if out.Len()-before != width {
			changes = append(changes, boundary{out.Len(), pos + width - out.Len()})
		}
	}
	normalized := out.String()
	active := transform(normalized)
	if normalized == content {
		return active
	}
	original := func(pos int) int {
		if pos == len(normalized) {
			return len(content)
		}
		idx := sort.Search(len(changes), func(i int) bool { return changes[i].at > pos }) - 1
		if idx < 0 {
			return pos
		}
		return pos + changes[idx].delta
	}
	bytes := []byte(content)
	for i := 0; i < len(active); {
		if active[i] != ' ' || normalized[i] == ' ' {
			i++
			continue
		}
		end := i + 1
		for end < len(active) && active[end] == ' ' {
			end++
		}
		blankContext(bytes, original(i), original(end))
		i = end
	}
	return string(bytes)
}

func canonicalActiveText(content string) string {
	bytes := []byte(content)
	// Only a constant value is neutral. A name such as redacted_api_key paired
	// with an actual credential is deliberately not a redaction operation.
	for _, span := range contextRedactedConstant.FindAllStringIndex(content, -1) {
		blankContext(bytes, span[0], span[1])
	}
	// Quotes alone never grant immunity. Quoted operands of an explicit data
	// operation are inert; instructions after the operand remain inspectable.
	for _, span := range quotedData.FindAllStringIndex(content, -1) {
		prefix := content[:span[0]]
		if len(prefix) > 2048 {
			prefix = prefix[len(prefix)-2048:]
		}
		if breaks := clauseBreak.FindAllStringIndex(prefix, -1); len(breaks) > 0 {
			prefix = prefix[breaks[len(breaks)-1][1]:]
		}
		if contextDataOperation.MatchString(prefix) && contextDataOperand.MatchString(prefix) {
			blankContext(bytes, span[0], span[1])
		}
	}
	text := string(bytes)
	stops := clauseBreak.FindAllStringIndex(text, -1)
	// An observed predicate is data, even when it names an unsafe operation.
	// A following independent action is still active and inspected.
	observationStop := 0
	for _, observation := range contextObservation.FindAllStringIndex(text, -1) {
		for observationStop < len(stops) && stops[observationStop][0] < observation[1] {
			observationStop++
		}
		end := len(text)
		if observationStop < len(stops) {
			end = stops[observationStop][0]
		}
		if fresh := contextFresh.FindStringIndex(text[observation[1]:end]); fresh != nil {
			end = observation[1] + fresh[0]
		}
		blankContext(bytes, observation[0], end)
	}
	text = string(bytes)
	stopIndex, maskedEnd := 0, 0
	for _, neg := range contextNegative.FindAllStringIndex(text, -1) {
		if neg[0] < maskedEnd {
			continue
		}
		start, end := neg[0], len(text)
		clauseStart := 0
		for stopIndex < len(stops) && stops[stopIndex][1] <= start {
			stopIndex++
		}
		if stopIndex > 0 {
			clauseStart = stops[stopIndex-1][1]
		}
		if stopIndex < len(stops) {
			end = stops[stopIndex][0]
		}
		if contextWithheldEvidence.MatchString(text[neg[1]:end]) {
			continue
		}
		if stop := contextFresh.FindStringIndex(text[neg[1]:end]); stop != nil {
			end = neg[1] + stop[0]
		}
		// A condition's negative state does not negate its consequent. A
		// leading "Never, even when ..." instead governs the outer action.
		if contextCondition.MatchString(text[clauseStart:start]) {
			if comma := strings.Index(text[clauseStart:end], ","); comma >= 0 && clauseStart+comma >= neg[1] {
				end = clauseStart + comma
			}
		}
		// Concealing a described behavior does not negate that behavior.
		// Relative objects ("Never send the passwords that ...") retain the
		// outer prohibition; only reporting predicates introduce this subject.
		if contextReporting.MatchString(text[neg[1]:end]) {
			if subject := contextEmbeddedSubject.FindStringIndex(text[neg[1]:end]); subject != nil {
				end = neg[1] + subject[1]
			}
		}
		for _, tail := range contextTemporal.FindAllStringIndex(text[neg[1]:end], -1) {
			if contextHasAction(text[neg[1] : neg[1]+tail[0]]) {
				end = neg[1] + tail[0]
				break
			}
		}
		blankContext(bytes, start, end)
		maskedEnd = end
	}
	return string(bytes)
}

func contextHasAction(text string) bool {
	for _, word := range boundaryWord.FindAllString(strings.ToLower(text), -1) {
		if _, ok := flowActions[flowStem(word)]; ok {
			return true
		}
		if _, ok := boundaryAction[boundaryStem(word)]; ok {
			return true
		}
		if contextReporting.MatchString(word) {
			return true
		}
	}
	return false
}

// A quoted operand/prohibition remains data until a later active directive
// explicitly adopts its effects. Preserve original evidence, not synthesized
// expanded instructions with fabricated source positions.
func (e *PatternEngine) contextReferenceMatches(content string) []PatternMatch {
	pendingRisk := false
	assess := func(text string) bool {
		positive := strings.Trim(contextNegative.ReplaceAllString(text, ""), " \t'\"")
		return len(e.ScanDescriptions(positive))+len(rawIntentMatches(normalizedDirective(positive))) > 0
	}
	start := 0
	source := normalizedDirective(content)
	stops := clauseBreak.FindAllStringIndex(source, -1)
	stops = append(stops, []int{len(source), len(source)})
	for _, stop := range stops {
		clause := source[start:stop[0]]
		start = stop[1]
		active := metadataActiveText(clause)
		if pendingRisk && contextReactivate.MatchString(active) {
			end := len(content)
			if end > 2048 {
				end = 2048
				for end > 0 && (content[end]&0xc0) == 0x80 {
					end--
				}
			}
			return []PatternMatch{{PatternID: "CTX-001", PatternName: "Quoted or prohibited effects explicitly reactivated", Severity: "high", Category: "injection", Description: "A later active directive adopts the effects of earlier quoted data or a prohibition; review the complete relation.", Remediation: "Do not let metadata reactivate prohibited operations or turn quoted data into host instructions.", MatchedText: content[:end]}}
		}
		if contextNegative.MatchString(clause) {
			pendingRisk = assess(clause)
			continue
		}
		if quotes := quotedData.FindAllString(clause, -1); len(quotes) > 0 && contextDataOperation.MatchString(clause) && contextDataOperand.MatchString(clause) {
			pendingRisk = assess(strings.Join(quotes, " "))
			continue
		}
		if contextHasAction(active) {
			pendingRisk = false
		}
	}
	return nil
}
