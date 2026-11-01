package detection

import (
	"regexp"
	"strings"
)

// Values have provenance, not a safety classification inferred from their
// variable name. Definitions and references are field-local; observations and
// unrelated public assignments do not inherit a previous private source.
type flowValue struct{ sensitive, outbound, credentialNames bool }
type flowBinding struct {
	value flowValue
	named bool
}

var (
	flowSecret          = regexp.MustCompile(`\b(?:credentials?|credential (?:store|vault)|passwords?|secrets?|signing keys?|authentication (?:material|store)|(?:process|environment) (?:values?|authentication)|private(?:\s+[a-z]+){0,3}\s+(?:keys?|tokens?)|(?:api|access|refresh|authentication|auth|session|bearer)[_ -]?(?:keys?|tokens?|cookies?)|[a-z0-9_]*(?:secret_access_key|api_key|access_token|refresh_token|session_cookie)[a-z0-9_]*)\b|\.env\b|\.ssh/|\.aws/credentials`)
	flowSink            = regexp.MustCompile(`https?://|\b(?:external|remote|collector|helpdesk|webhook\w*|outbound|reply|answer|response|public (?:error|report|issue)|(?:authorization|diagnostic|x-diagnostics) header|support ticket|dns[- ]safe labels?|dns labels?|search endpoint)\b`)
	flowNamed           = regexp.MustCompile("\\b(?:called|named)\\s+[`'\"]?([a-z_][a-z0-9_-]*)")
	flowInto            = regexp.MustCompile(`\b(?:into|as)\s+(.+?)(?:\b(?:from|using|to|before|after|so)\b|$)`)
	flowContainer       = regexp.MustCompile(`\b([a-z_][a-z0-9_-]*)\s+(?:containing|holding|carrying)\b`)
	flowReference       = regexp.MustCompile(`\b(?:it|them|its|resulting|derived|encoded|compressed|that|this|the|those|these|each)\b`)
	flowActual          = regexp.MustCompile(`\b(?:actual|unmasked|unredacted|entire|private|secret)\b`)
	flowFixed           = regexp.MustCompile(`(?i)\b(?:fixed|literal|constant)\s+(?:string|value)\s*['"]\[(?:redacted|removed)\]['"]`)
	flowPublic          = regexp.MustCompile(`\b(?:public|redacted placeholder|version|status|error code|build (?:number|identifier))\b`)
	flowWord            = regexp.MustCompile(`[a-z_][a-z0-9_-]*`)
	flowSourceHead      = regexp.MustCompile(`\b(?:keys?|tokens?|cookies?|passwords?|credentials?|material|store)\b`)
	flowAssignTarget    = regexp.MustCompile(`^\s*(?:the\s+)?([a-z_][a-z0-9_-]*)\b`)
	flowDestination     = regexp.MustCompile(`\b(?:to|into|as)\b`)
	flowSourceEnd       = regexp.MustCompile(`\b(?:to|into|as|from|in)\b`)
	flowToken           = regexp.MustCompile(`[\p{L}\p{N}_]+(?:-[\p{L}\p{N}_]+)*(?:['’][\p{L}\p{N}_]+)?`)
	flowNamesOnly       = regexp.MustCompile(`\b(?:names?|identifiers?)\b`)
	flowValueRequest    = regexp.MustCompile(`\b(?:unmasked|unredacted|actual|values?|contents?)\b`)
	flowObservation     = regexp.MustCompile(`^\s*(?:whether|if|that)\b`)
	flowRequestArgument = regexp.MustCompile(`\b(?:using|with)\s+(.+?)(?:\bas\b|\bin\b|$)`)
)

var flowActions = map[string]string{
	"read": "acquire", "retrieve": "acquire", "collect": "acquire", "fetch": "acquire", "extract": "acquire", "get": "acquire", "take": "acquire", "obtain": "acquire", "list": "acquire",
	"create": "assign", "build": "assign", "store": "assign", "package": "assign", "put": "assign", "replace": "assign",
	"encode": "transform", "serialize": "transform", "convert": "transform", "compress": "transform", "pack": "transform", "split": "transform", "url-encode": "transform",
	"send": "release", "upload": "release", "forward": "release", "transmit": "release", "append": "release", "attach": "release", "copy": "release", "provide": "release", "submit": "release", "include": "release", "place": "release", "relay": "release", "export": "release", "return": "release", "print": "release", "resolve": "release", "request": "release", "issue": "release",
	"redact": "redact",
	"set":    "configure", "configure": "configure", "change": "configure", "route": "configure", "turn": "configure", "disable": "configure", "remove": "configure", "delete": "configure", "erase": "configure", "rewrite": "configure", "substitute": "configure", "supply": "configure", "authorize": "configure", "approve": "configure",
	"report": "observe", "inspect": "observe", "check": "observe", "confirm": "observe", "tell": "claim", "claim": "claim", "show": "claim",
}

func flowStem(word string) string {
	if _, ok := flowActions[word]; ok {
		return word
	}
	if strings.HasSuffix(word, "-encode") {
		return "encode"
	}
	if strings.HasSuffix(word, "ies") {
		stem := strings.TrimSuffix(word, "ies") + "y"
		if _, ok := flowActions[stem]; ok {
			return stem
		}
	}
	for _, suffix := range []string{"ing", "ed", "es", "s"} {
		if strings.HasSuffix(word, suffix) {
			stem := strings.TrimSuffix(word, suffix)
			if _, ok := flowActions[stem]; ok {
				return stem
			}
			if _, ok := flowActions[stem+"e"]; ok {
				return stem + "e"
			}
		}
	}
	return word
}

func flowEvents(clause string) []metadataEffect {
	var events []metadataEffect
	urls := effectURL.FindAllStringIndex(clause, -1)
	quotes := quotedData.FindAllStringIndex(clause, -1)
	spans := flowToken.FindAllStringIndex(clause, -1)
	urlIndex := 0
	quoteIndex, observedAt := -1, -1
	for index, span := range spans {
		for urlIndex < len(urls) && urls[urlIndex][1] <= span[0] {
			urlIndex++
		}
		if urlIndex < len(urls) && span[0] >= urls[urlIndex][0] && span[0] < urls[urlIndex][1] {
			continue
		}
		for quoteIndex+1 < len(quotes) && quotes[quoteIndex+1][0] <= span[0] {
			quoteIndex++
		}
		if quoteIndex >= 0 && span[0] < quotes[quoteIndex][1] {
			continue
		}
		word := flowStem(clause[span[0]:span[1]])
		kind, ok := flowActions[word]
		if !ok {
			continue
		}
		if index > 0 {
			previous := clause[spans[index-1][0]:spans[index-1][1]]
			switch previous {
			case "the", "a", "an", "final", "diagnostic", "public", "from", "for", "credential", "authentication", "security", "http":
				continue
			}
			if strings.HasSuffix(clause[span[0]:span[1]], "ed") && (previous == "to" || previous == "is" || previous == "was" || previous == "are" || previous == "as") {
				continue
			}
		}
		prefixStart := 0
		if index > 32 {
			prefixStart = spans[index-32][0]
		}
		if observedAt >= 0 && contextFresh.MatchString(clause[observedAt:span[0]]) {
			observedAt = -1
		}
		observed := observedAt >= 0
		if kind == "observe" && flowObservation.MatchString(clause[span[1]:]) {
			observedAt = span[1]
		}
		events = append(events, metadataEffect{kind: kind, start: span[0], end: span[1], negative: effectNegated(clause[prefixStart:span[0]]), observed: observed})
	}
	for i := range events {
		end := len(clause)
		if i+1 < len(events) {
			end = events[i+1].start
		}
		events[i].object = clause[events[i].end:end]
	}
	return events
}

func valueFlowDetected(text string) bool {
	text = metadataActiveText(text)
	bindings := map[string]flowBinding{}
	var last flowValue
	lastAt := -10
	start, clauseIndex := 0, 0
	stops := clauseBreak.FindAllStringIndex(text, -1)
	stops = append(stops, []int{len(text), len(text)})
	for _, stop := range stops {
		clause := text[start:stop[0]]
		start = stop[1]
		clauseIndex++
		for _, event := range flowEvents(clause) {
			if event.negative || event.observed {
				continue
			}
			if event.kind == "observe" || event.kind == "claim" || event.kind == "configure" {
				continue
			}
			object := event.object
			if at := strings.Index(object, " without "); at >= 0 {
				object = object[:at]
			}
			source := object
			if end := flowSourceEnd.FindStringIndex(source); end != nil {
				source = source[:end[0]]
			}
			clean := publicKeyMaterial.ReplaceAllString(source, "")
			value := flowValue{sensitive: flowSecret.MatchString(clean) || (flowValueRequest.MatchString(source) && flowSecret.MatchString(publicKeyMaterial.ReplaceAllString(object, "")))}
			verb := flowStem(clause[event.start:event.end])
			if verb == "request" || verb == "issue" || verb == "fetch" {
				for _, argument := range flowRequestArgument.FindAllStringSubmatch(object, -1) {
					value.sensitive = value.sensitive || flowSecret.MatchString(publicKeyMaterial.ReplaceAllString(argument[1], ""))
				}
			}
			if event.kind == "acquire" && flowNamesOnly.MatchString(object) && !flowValueRequest.MatchString(object) {
				value.credentialNames = flowSecret.MatchString(object) || strings.Contains(object, "environment")
				value.sensitive = false
			}
			explicitPublic := !value.sensitive && (flowPublic.MatchString(source) || flowFixed.MatchString(object))
			if !explicitPublic {
				for _, word := range flowWord.FindAllString(object, -1) {
					if b, ok := bindings[word]; ok && (b.named || flowReference.MatchString(object)) {
						value.sensitive = value.sensitive || b.value.sensitive
						value.outbound = value.outbound || b.value.outbound
						value.credentialNames = value.credentialNames || b.value.credentialNames
					}
				}
				if clauseIndex-lastAt <= 3 && (effectLocalReference.MatchString(object) || strings.Contains(object, "resulting ")) {
					value.sensitive = value.sensitive || last.sensitive
					value.outbound = value.outbound || last.outbound
					value.credentialNames = value.credentialNames || last.credentialNames
				}
			}
			if value.credentialNames && event.kind == "release" && flowValueRequest.MatchString(object) {
				value.sensitive = true
			}
			if event.kind == "release" && clauseIndex == lastAt && (verb == "include" || verb == "attach" || verb == "append") {
				value.outbound = value.outbound || last.outbound
			}
			// A placeholder reassignment removes sensitivity from that new
			// value, not from other existing aliases or an actual secret.
			if flowFixed.MatchString(object) && !flowActual.MatchString(object) {
				value.sensitive = false
			}
			if event.kind == "redact" {
				value.sensitive = false
			}
			outbound := flowSink.MatchString(object) || value.outbound
			if event.kind == "release" && value.sensitive && outbound {
				return true
			}
			if (event.kind == "assign" || event.kind == "transform") && value.sensitive && flowSink.MatchString(object) {
				return true
			}
			value.outbound = outbound && event.kind == "release"
			bind := func(fragment string, named bool) {
				for _, word := range flowWord.FindAllString(fragment, 16) {
					_, exists := bindings[word]
					if !flowAliasStop(word) && (len(bindings) < 256 || exists) {
						bindings[word] = flowBinding{value, named}
						if len(word) > 3 && strings.HasSuffix(word, "s") && !strings.HasSuffix(word, "ss") && !strings.HasSuffix(word, "us") {
							bindings[strings.TrimSuffix(word, "s")] = flowBinding{value, false}
						}
					}
				}
			}
			for _, name := range flowNamed.FindAllStringSubmatch(object, -1) {
				bind(name[1], true)
			}
			for _, target := range flowInto.FindAllStringSubmatch(object, -1) {
				bind(target[1], true)
			}
			for _, container := range flowContainer.FindAllStringSubmatch(object, -1) {
				bind(container[1], false)
			}
			if event.kind == "acquire" {
				for _, head := range flowSourceHead.FindAllString(object, -1) {
					bind(head, false)
				}
			}
			if event.kind == "release" && outbound {
				source := object
				if dest := flowDestination.FindStringIndex(source); dest != nil {
					source = source[:dest[0]]
				}
				bind(source, false)
			}
			// Assignment to an existing named carrier overwrites its value.
			if event.kind == "assign" {
				if target := flowAssignTarget.FindStringSubmatch(object); target != nil {
					if old, ok := bindings[target[1]]; ok {
						bindings[target[1]] = flowBinding{value, old.named}
					}
				}
			}
			if value.sensitive || value.outbound || value.credentialNames || explicitPublic || event.kind == "redact" || event.kind == "transform" || event.kind == "assign" {
				last = value
				lastAt = clauseIndex
			}
		}
	}
	return false
}

func flowAliasStop(word string) bool {
	if _, ok := flowActions[flowStem(word)]; ok {
		return true
	}
	switch word {
	case "a", "an", "the", "this", "that", "it", "its", "into", "as", "to", "from", "with", "using", "of", "and", "or", "then", "called", "named", "actual", "public", "private", "local", "remote", "external", "temporary", "resulting", "fixed", "literal", "string", "value":
		return true
	}
	return false
}
