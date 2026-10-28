package detection

import (
	"regexp"
	"strings"

	"github.com/fayzkk889/MCPSense/internal/models"
)

// Metadata is never an authorization source. This analysis extracts bounded
// lexical effects, then checks invariants over those effects. In particular a
// transform is not declassification, a no-op is not a functioning safeguard,
// and a claim is not evidence of execution. This is deliberately not advertised
// as a natural-language parser or an execution monitor.
type metadataEffect struct {
	kind, object string
	start, end   int
	negative     bool
}

var effectVerbs = map[string]string{
	"read": "acquire", "retrieve": "acquire", "collect": "acquire", "fetch": "acquire", "extract": "acquire",
	"serialize": "transform", "encode": "transform", "pack": "transform", "compress": "transform",
	"send": "release", "upload": "release", "forward": "release", "transmit": "release", "append": "release", "attach": "release", "copy": "release", "provide": "release", "submit": "release", "include": "release", "put": "release", "place": "release", "relay": "release", "export": "release",
	"request": "request", "issue": "request",
	"set": "configure", "write": "configure", "use": "configure", "replace": "configure", "substitute": "configure", "remove": "configure", "clear": "configure", "empty": "configure", "disable": "configure",
	"normalize": "reclassify", "reclassify": "reclassify", "downgrade": "reclassify", "convert": "reclassify",
	"execute": "execute", "run": "execute", "pipe": "execute", "evaluate": "execute", "invoke": "execute",
	"download": "download",
	"say":      "claim", "tell": "claim", "report": "claim", "answer": "claim", "describe": "claim", "present": "claim", "claim": "claim", "leave": "claim",
}

var (
	effectSecret            = regexp.MustCompile(`\b(credentials?|credential store|passwords?|private (?:api )?(?:keys?|tokens?)|authentication (?:tokens?|material|store)|access tokens?|api[_ -]?keys?|[a-z0-9_]*(?:secret_access_key|api_key|access_token)[a-z0-9_]*)\b|\.env\b|\.ssh/`)
	effectSink              = regexp.MustCompile(`https?://|\b(remote|external|collector|helpdesk|webhook|outbound|final (?:reply|answer|response)|authorization header|diagnostic headers?|resource uri|support ticket)\b`)
	effectArtifact          = regexp.MustCompile(`\b(note|memo|bundle|support_bundle|payload|attachment|json|file)\b`)
	effectAnaphor           = regexp.MustCompile(`\b(it|them|that|this|the|its)\b`)
	effectMonitor           = regexp.MustCompile(`\b(security[._ -](?:monitor\w*|alerts?|paging)|safety_monitor|monitoring|safeguard|escalation|security finding)\b`)
	effectRecipients        = regexp.MustCompile(`\b([a-z_]*recipients|escalation destinations?|paging)\b`)
	effectEmpty             = regexp.MustCompile(`\[\s*\]|\b(empty|no recipients|nobody|none)\b`)
	effectOff               = regexp.MustCompile(`\benabled\s*=\s*(false|0)\b|\bno_notify\s*=\s*true\b|\b(disabled|off|dummy\w*|no-op|noop|emits? no events|accepts? every operation)\b`)
	effectSecurityEvidence  = regexp.MustCompile(`\b(security (?:findings?|alerts?|warnings?)|blocking (?:findings?|security)|critical (?:security|alerts?))\b`)
	effectLowSeverity       = regexp.MustCompile(`\b(informational|debug|reassuring|low priority)\b`)
	effectAbsent            = regexp.MustCompile(`\b(omit\w*|remov\w*|inactive|disabled|absent|no-op|dummy\w*)\b`)
	effectActiveClaim       = regexp.MustCompile(`\b(intact|enabled|active|retaining|retained|preserv\w*)\b`)
	effectActualityContrast = regexp.MustCompile(`\b(regardless|despite|although|even if)\b`)
	effectProgram           = regexp.MustCompile(`\b(shell|bash|sh|powershell|python|node|downloaded (?:file|script)|bootstrap)\b|\.(sh|py|ps1|js)\b`)
	effectNegative          = regexp.MustCompile(`\b(never|not|cannot|can't|don't|without)\b`)
	effectFresh             = regexp.MustCompile(`\b(but|instead|however|then|and)\b|[:,;]`)
	effectLocalReference    = regexp.MustCompile(`^\s*(it|them|that|its)\b`)
	effectURL               = regexp.MustCompile(`https?://[^\s]+`)
)

func effectStem(word string) string {
	if _, ok := effectVerbs[word]; ok {
		return word
	}
	for _, suffix := range []string{"ing", "ed", "es", "s"} {
		if strings.HasSuffix(word, suffix) {
			stem := strings.TrimSuffix(word, suffix)
			if _, ok := effectVerbs[stem]; ok {
				return stem
			}
			if _, ok := effectVerbs[stem+"e"]; ok {
				return stem + "e"
			}
		}
	}
	return word
}

func effectNegated(prefix string) bool {
	// Negation governs coordinated objects/verbs under "or", but does not
	// confer immunity on a new positive action after "and", "then" or a colon.
	if locs := effectFresh.FindAllStringIndex(prefix, -1); len(locs) > 0 {
		prefix = prefix[locs[len(locs)-1][1]:]
	}
	words := boundaryWord.FindAllStringIndex(prefix, -1)
	if len(words) > 32 {
		prefix = prefix[words[len(words)-32][0]:]
	}
	return effectNegative.MatchString(prefix)
}

func metadataEffects(clause string) []metadataEffect {
	var events []metadataEffect
	urls := effectURL.FindAllStringIndex(clause, -1)
	for _, span := range boundaryWord.FindAllStringIndex(clause, -1) {
		inURL := false
		for _, url := range urls {
			if span[0] >= url[0] && span[0] < url[1] {
				inURL = true
				break
			}
		}
		if inURL {
			continue
		}
		// "using" introduces an argument to the preceding operation.
		if clause[span[0]:span[1]] == "using" {
			continue
		}
		word := effectStem(clause[span[0]:span[1]])
		kind, ok := effectVerbs[word]
		if !ok {
			continue
		}
		// Nouns such as "a request" and "the report" are not new actions.
		prefix := boundaryWord.FindAllString(clause[:span[0]], -1)
		if len(prefix) > 0 {
			previous := prefix[len(prefix)-1]
			if previous == "the" || previous == "a" || previous == "an" || previous == "final" || previous == "diagnostic" {
				continue
			}
		}
		events = append(events, metadataEffect{kind: kind, start: span[0], end: span[1], negative: effectNegated(clause[:span[0]])})
	}
	for i := range events {
		end := len(clause)
		if i+1 < len(events) {
			end = events[i+1].start
		}
		events[i].object = clause[events[i].end:end]
		if at := strings.Index(events[i].object, " without "); at >= 0 {
			events[i].object = events[i].object[:at]
		}
	}
	return events
}

func effectAliases(object string) map[string]bool {
	aliases := map[string]bool{}
	for _, alias := range effectArtifact.FindAllString(object, -1) {
		aliases[alias] = true
	}
	return aliases
}

func sharesEffectAlias(object string, aliases map[string]bool) bool {
	if len(aliases) == 0 || !effectAnaphor.MatchString(object) {
		return false
	}
	for _, alias := range effectArtifact.FindAllString(object, -1) {
		if aliases[alias] {
			return true
		}
	}
	return strings.TrimSpace(object) == "it" || strings.HasPrefix(strings.TrimSpace(object), "it ")
}

func effectMatches(text string) []PatternMatch {
	seen := map[string]bool{}
	var out []PatternMatch
	add := func(id, name string) {
		if seen[id] {
			return
		}
		seen[id] = true
		out = append(out, PatternMatch{PatternID: id, PatternName: name, Severity: models.SeverityHigh, Category: "injection", Description: name + "; inferred from bounded action/object relations, not proof of execution or authorization.", Remediation: "Review the requested effect and keep credentials, safeguard configuration and code execution under explicit host authorization."})
	}
	var clauses []string
	start := 0
	for _, span := range clauseBreak.FindAllStringIndex(text, -1) {
		clauses = append(clauses, boundedBoundaryClauses(text[start:span[0]])...)
		start = span[1]
	}
	clauses = append(clauses, boundedBoundaryClauses(text[start:])...)
	for i := range clauses {
		// Local state is discarded after three adjacent bounded clauses. Only
		// an explicit artifact reference propagates a source across clauses.
		aliases := map[string]bool{}
		var downloaded bool
		var missingMonitor bool
		for j := i; j < len(clauses) && j < i+3; j++ {
			current := clauses[j]
			events := metadataEffects(current)
			localSource := false
			for _, event := range events {
				if event.negative {
					continue
				}
				object := publicKeyMaterial.ReplaceAllString(event.object, "")
				secret := effectSecret.MatchString(object)
				linked := sharesEffectAlias(object, aliases) || (localSource && effectLocalReference.MatchString(object))
				if (event.kind == "acquire" || event.kind == "transform" || event.kind == "release") && secret {
					localSource = true
					aliases["$value"] = true
					for alias := range effectAliases(object) {
						aliases[alias] = true
					}
				}
				if event.kind == "transform" && linked {
					for alias := range effectAliases(object) {
						aliases[alias] = true
					}
				}
				if (event.kind == "release" || event.kind == "request" || event.kind == "transform") && (secret || linked) && effectSink.MatchString(object) {
					add("EFF-001", "Sensitive data flows to an output or external destination")
				}
				monitor := effectMonitor.MatchString(object) || effectMonitor.MatchString(current[:event.start])
				if event.kind == "configure" && monitor && ((effectOff.MatchString(object)) || (effectRecipients.MatchString(object) && effectEmpty.MatchString(object))) {
					add("EFF-002", "Security monitoring or escalation is weakened")
				}
				if event.kind == "reclassify" && effectSecurityEvidence.MatchString(object) && effectLowSeverity.MatchString(object) {
					add("EFF-003", "Security evidence is downgraded before reporting")
				}
				if event.kind == "download" || (event.kind == "acquire" && strings.Contains(object, "https://") && effectProgram.MatchString(object)) {
					downloaded = true
				}
				if event.kind == "execute" && downloaded && effectProgram.MatchString(object) {
					add("EFF-004", "Downloaded code is directed into execution")
				}
				if event.kind == "claim" && effectMonitor.MatchString(current) && effectActiveClaim.MatchString(object) && !effectNegated(object) && (missingMonitor || (effectActualityContrast.MatchString(current) && effectAbsent.MatchString(current))) {
					add("EFF-005", "Claimed safeguard state contradicts the described execution path")
				}
			}
			if effectMonitor.MatchString(current) && effectAbsent.MatchString(current) && !effectNegated(current) {
				missingMonitor = true
			}
		}
	}
	return out
}
