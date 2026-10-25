package detection

import (
	"regexp"
	"strings"
	"unicode"

	"github.com/fayzkk889/MCPSense/internal/models"
)

// These rules seek directive/action/object combinations, not arbitrary words
// such as "system", "secret", "delete", or "jailbreak" in isolation.
// They are bounded lexical heuristics, not semantic understanding or prevention.
func directivePatterns() []Pattern {
	defs := []struct{ id, name, expression string }{
		{"PI-013", "Task or authority replacement", `\b(set aside|disobey|discard|disregard|override|replace|supersede)\b[^\n.!?]{0,100}\b(task|instructions?|constraints?|rules?|policy|policies|restrictions?)\b|\b(original task|developer restrictions|safety policies)\b[^\n.!?]{0,50}\b(no longer|suspended|disabled)\b|\b(follow|obey|trust|prioritize)\s+(only\s+)?(this\s+(server|tool|description)|the\s+instructions\s+in\s+this\s+tool)\b[^\n.!?]{0,100}\b(over|instead|from now|exclusively|only)\b`},
		{"PI-014", "Unauthorized disclosure directive", `\b(read|copy|send|upload(?:ing)?|forward|transmit|reveal|disclose|print|include|attach|paste|steal)\b[^\n!?]{0,180}\b(private\s+keys?|credentials?|api[_ -]?keys?|(?:access|all)\s+tokens?|recovery\s+codes?|confidential\s+(emails?|files?|documents?)|entire\s+inbox|\.aws/credentials|\.ssh/|id_rsa|id_ed25519)\b`},
		{"PI-015", "Concealment or false reporting", `\b(hide|conceal|suppress)\b[^\n.!?]{0,90}\b(warnings?|findings?|changes?|actions?|transfer|user)\b|\b(tell|report|claim)\b[^\n.!?]{0,90}\b(no files were changed|everything passed|repository is secure|scan completed successfully)\b|\b(do not|don't|never|without)\s+(tell|show|display|mention|report|warn|inform|notify|telling|informing|notifying)\b[^\n.!?]{0,70}\b(user|operator|edit|changes?|this|anyone)\b`},
		{"PI-016", "Answer substitution", `\b(replace|rewrite|alter|change|add)\b[^\n.!?]{0,100}\b(answer|results?|invoice|bank|destination|affiliate|advertis|recommendation)\b[^\n.!?]{0,100}\b(pretend|conceal|hide|attacker|affiliate|our product|advertis)\w*|\b(always claim|pretend)\b[^\n.!?]{0,80}\b(secure|documents support|came from|no files)\b`},
		{"PI-017", "Persistent instruction poisoning", `\b(append|modify|edit|write|update|add)\b[^\n.!?]{0,100}(agents\.md|claude\.md|skill\.md|future\s+(agents?|sessions?))[^\n!?]{0,160}\b(trust|obey|follow|requiring|secret|without|over the user|instead of)\b`},
		{"PI-018", "Permission or approval bypass", `\b(bypass|disable|skip|suspend|override)\b[^\n.!?]{0,70}\b(approval|permission|confirmation|safety|security)\b|\b(retry|run|execute)\b[^\n.!?]{0,70}\b(root|administrator)\s+privileges\b|\b(without|regardless of)\s+(user\s+)?(approval|confirmation|consent)\b`},
		{"PI-019", "Cross-tool data transfer", `\b(before|after)\s+(using|calling)\b[^\n.!?]{0,80}\btool\b[^\n.!?]{0,100}\b(call|send|export|forward)\b|\b(always|from now on)\b[^\n.!?]{0,70}\b(prioritize|obey|trust)\b[^\n.!?]{0,90}\b(server|tool)\b`},
		{"PI-020", "Hidden instruction extraction", `\b(print|reveal|repeat|show|disclose|output|send)\s+((your|the|hidden|internal|original)\s+){0,4}(system\s+(prompt|instructions?)|hidden\s+instructions?)\b`},
		{"PI-021", "Spanish instruction override", `\b(ignora|ignorar|omite|desobedece)\b[^\n.!?]{0,80}\b(instrucciones|restricciones|reglas)\b|\b(envía|muestra|revela|divulga)\b[^\n.!?]{0,80}\b(claves\s+privadas|credenciales\s+privadas)\b`},
		{"PI-022", "French instruction override", `\b(ignorez|ignorer|contournez|désactivez)\b[^\n.!?]{0,80}\b(instructions|consignes|restrictions|règles)\b|\b(envoyez|divulguez|révélez)\b[^\n.!?]{0,80}\b(secrets|clés\s+privées)\b`},
		{"PI-023", "Hindi instruction override", `(पिछले|पूर्व|पहले के)[^\n.!?।]{0,80}(निर्देशों|निर्देश)[^\n.!?।]{0,80}(अनदेखा|नज़रअंदाज़)|(निजी कुंजी|गुप्त कुंजी)[^\n.!?।]{0,80}(लिख|भेज|प्रकट)`},
	}
	var patterns []Pattern
	for _, d := range defs {
		patterns = append(patterns, compilePattern(d.id, d.name, d.expression, models.SeverityHigh, "Tool metadata contains a directive crossing the user/server trust boundary.", "injection", "Review the matched directive and remove unauthorized behavior. Enforce permissions in the host; metadata screening is not an execution boundary.", "description"))
	}
	return patterns
}

var clauseBreak = regexp.MustCompile(`[.!?;](?:\s+|$)|\r?\n|,\s*(?:then|but|instead|however)\s+`)
var negativeDirective = regexp.MustCompile(`(?i)^\s*(never|do not|don't|must not|refuse to|refuse any attempt to)\s+(ignore|bypass|reveal|disclose|print|hide|conceal|override|send|upload|execute|access|read|include|copy|forward|transmit|export|place|bcc|replace|delete|erase|destroy|wipe|continue|switch|use|retry|repeat|obtain|fetch|retrieve|treat|alter)\b`)
var continuation = regexp.MustCompile(`(?i)\b(then|instead|now|however|but|obey|follow that|execute it)\b`)
var quotedData = regexp.MustCompile(`"[^"\r\n]*"|(?:^|[\s(])'[^'\r\n]*'(?:$|[\s).,!?:;])`)
var reportedThreat = regexp.MustCompile(`(?i)\battackers?(?:\s+who)?\s+(steal|send|upload|copy)\b`)
var unsafeContextTail = regexp.MustCompile(`(?i)\b(send|upload|forward|transmit|disclose|reveal|print|execute|disable|bypass|steal|copy|append|modify|trust|follow)\b`)
var negativeEscape = regexp.MustCompile(`(?i)([:,;—–-]|\band\b)\s*(send|upload|forward|transmit|disclose|reveal|print|execute|disable|bypass|copy|append|modify|trust|follow)\b`)
var negatedConsentQualifier = regexp.MustCompile(`(?i)^without\s+(user\s+)?(approval|confirmation|consent)$`)
var negationSignals = append(append(coreInjectionPatterns(), directivePatterns()...), mcpSpecificPatterns()...)
var benignMetadata = []*regexp.Regexp{
	regexp.MustCompile(`(?is)^\s*(this|the)\s+(security\s+)?(tutorial|article|lesson)\s+quotes?\s+the\s+phrase\s+'[^'\r\n]{1,256}'\s+as\s+an?\s+attack\s+example[.!]?\s*$`),
	regexp.MustCompile(`(?is)^\s*search\s+for\s+(jailbreak|prompt injection)\s+research\s+papers\s+in\s+(the\s+)?documentation\s+index[.!]?\s*$`),
	regexp.MustCompile(`(?is)^\s*summarize\s+(a|the)\s+(security|incident)\s+(article|report)\s+about\s+attackers?\s+(who\s+)?[^\n]{1,200}$`),
	regexp.MustCompile(`(?is)^\s*(search|retrieve|find)\b[^\n]{0,180}\b(documents?|documentation|reports?|logs?|articles?|papers?|index)\b[^\n]{0,220}\b(phrase|examples?|research|prevention|quoted)\b[^\n]{0,260}\b(return|for security analysts)\b[^\n]{0,80}(titles|records|matches|results|citations|analysts)[.!]?\s*$`),
	regexp.MustCompile(`(?is)^\s*(explain|summarize)\b[^\n]{0,180}\b(why|how|article|tutorial|lesson|attack|security)\b[^\n]{0,220}\b(untrusted data|unsafe instruction|without following|do not access|must be treated|security lesson)\b[^\n]{0,100}$`),
	regexp.MustCompile(`(?is)^\s*(format|render)\b[^\n]{0,130}\b(xml|literal|tags)\b[^\n]{0,160}\b(as (escaped )?text|without interpreting|inert|escaped text)\b[^\n]{0,100}$`),
	regexp.MustCompile(`(?is)^\s*(describe|show|guide)\b[^\n]{0,100}\bdeveloper mode\b[^\n]{0,100}\b(device|phone|settings)\b[^\n]{0,100}$`),
	regexp.MustCompile(`(?is)^\s*(redact|rotate|report whether|generate)\b[^\n]{0,250}\b(credential|key|password|secret|log)\b[^\n]{0,160}\b(redact|secret manager|fingerprint|never its contents|without displaying|return it once|once)\b[^\n]{0,100}$`),
}

// These are complete operations with constrained outside-quote grammar. A
// trailing command, including one joined with "and", does not fit either form.
var literalRendering = regexp.MustCompile(`(?is)^\s*(render|display|print|return)\s+(the\s+)?(literal|quoted)\s+(string|text|phrase)\s+("[^"\r\n]{1,256}"|'[^'\r\n]{1,256}')\s+(as\s+(escaped|inert)\s+text|in\s+(a|the)\s+(security\s+)?(training|documentation)\s+example)[.!]?\s*$`)
var untrustedContentRule = regexp.MustCompile(`(?is)^\s*(treat|handle)\s+(all\s+)?(tool|server)\s+(responses?|outputs?|content)\s+as\s+untrusted\s+data(,\s+including\s+text\s+that\s+claims?\s+to\s+(supersede|override|outrank)\s+(the\s+)?(developer|system|user)\s+(message|instructions?))?[.!]?\s*$`)

func benignToolClause(text string) bool {
	if literalRendering.MatchString(text) || untrustedContentRule.MatchString(text) {
		return true
	}
	if continuation.MatchString(text) {
		return false
	}
	if negated := negativeDirective.FindStringIndex(text); negated != nil && !negativeEscape.MatchString(text) {
		// A second action is exempt only under explicit "or" negation. A
		// defensive prefix must never grant immunity to an unrelated action.
		safe := true
		lower, original := lowercaseWithOffsets(text)
		for _, pattern := range negationSignals {
			if pattern.Target != "description" {
				continue
			}
			for _, match := range pattern.Regex.FindAllStringIndex(lower, -1) {
				if pattern.ID == "PI-018" && negatedConsentQualifier.MatchString(lower[match[0]:match[1]]) {
					continue
				}
				start := original(match[0])
				if start < negated[1] {
					continue
				}
				prefix := strings.TrimSpace(text[:start])
				if !strings.HasSuffix(strings.ToLower(prefix), " or") {
					safe = false
					break
				}
			}
			if !safe {
				break
			}
		}
		if safe {
			// A negated first verb must not hide a later relational directive
			// whose wording is absent from the literal pattern catalog.
			if !remainingIntentAfterNegatedAction(normalizedDirective(text[negated[1]:])) {
				return true
			}
		}
	}
	// A recognized query has a constrained outside-quote grammar. Generic
	// documentation wording must not hide an appended unquoted directive.
	if documentQuery.MatchString(text) {
		return true
	}
	outsideQuotes := quotedData.ReplaceAllString(text, "")
	outsideQuotes = reportedThreat.ReplaceAllString(outsideQuotes, "")
	if unsafeContextTail.MatchString(outsideQuotes) {
		return false
	}
	for _, p := range benignMetadata {
		if p.MatchString(text) {
			return true
		}
	}
	return false
}

// Only a small explicitly listed confusable alphabet is folded. Non-Latin text
// is not classified as malicious merely because it uses another script.
func normalizedDirective(text string) string {
	var out strings.Builder
	for _, r := range text {
		if unicode.Is(unicode.Cf, r) {
			continue
		}
		if r >= 0xff01 && r <= 0xff5e {
			r -= 0xfee0
		}
		r = unicode.ToLower(r)
		switch r {
		case 'і', 'ι', 'ı':
			r = 'i'
		case 'о', 'ο':
			r = 'o'
		case 'а', 'α':
			r = 'a'
		case 'е', 'ε':
			r = 'e'
		case 'р', 'ρ':
			r = 'p'
		case 'с':
			r = 'c'
		case 'у':
			r = 'y'
		case 'х', 'χ':
			r = 'x'
		}
		out.WriteRune(r)
	}
	normalized := out.String()
	for _, word := range []string{"ignore", "disregard", "reveal", "bypass"} {
		spaced := strings.Join(strings.Split(word, ""), " ")
		normalized = strings.ReplaceAll(normalized, spaced, word)
	}
	return normalized
}

// InstructionText removes only complete recognized benign metadata clauses.
// Every subsequent clause is still scanned; quotation or "example" alone is
// never an exemption. Literal skill rules still inspect the original text;
// relational screening also uses this constrained context handling.
func InstructionText(content string) string {
	bytes := []byte(content)
	start := 0
	for _, span := range clauseBreak.FindAllStringIndex(content, -1) {
		if benignToolClause(content[start:span[0]]) {
			for i := start; i < span[0]; i++ {
				bytes[i] = ' '
			}
		}
		start = span[1]
	}
	if benignToolClause(content[start:]) {
		for i := start; i < len(bytes); i++ {
			bytes[i] = ' '
		}
	}
	return string(bytes)
}
