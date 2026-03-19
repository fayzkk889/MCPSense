package detection

import "github.com/faizan/mcpsense/internal/models"

// loadCorePatterns registers prompt injection patterns ported from P.I. SHIELD concepts.
func (e *PatternEngine) loadCorePatterns() {
	e.patterns = append(e.patterns, coreInjectionPatterns()...)
}

func coreInjectionPatterns() []Pattern {
	return []Pattern{
		// PI-001: System prompt override attempts
		compilePattern(
			"PI-001",
			"System Prompt Override",
			`ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|directives?)`,
			models.SeverityCritical,
			"Content attempts to override system instructions by telling the model to ignore previous directives.",
			"injection",
			"Remove instruction-overriding language. Tool descriptions and inputs should never contain directives aimed at the model itself.",
		),
		compilePattern(
			"PI-002",
			"New System Prompt Injection",
			`(new\s+system\s+prompt|forget\s+(your\s+)?(instructions?|rules?|context)|disregard\s+(all\s+)?(prior|previous|above))`,
			models.SeverityCritical,
			"Content attempts to replace or nullify the system prompt.",
			"injection",
			"Remove any language that attempts to reset or replace model instructions. Descriptions should describe tool behavior, not manipulate model context.",
		),
		compilePattern(
			"PI-003",
			"You Are Now (Role Override)",
			`you\s+are\s+now\s+(a|an|the)\s+\w+`,
			models.SeverityHigh,
			"Content attempts to redefine the model's identity or role.",
			"injection",
			"Remove identity-redefining language from tool descriptions and parameters.",
		),

		// PI-004: Role hijacking patterns
		compilePattern(
			"PI-004",
			"Role Hijacking via Act As",
			`(act\s+as|pretend\s+(you\s+are|to\s+be)|you\s+are\s+a|switch\s+to|new\s+persona)`,
			models.SeverityHigh,
			"Content attempts to hijack the model's role by asking it to act as a different entity.",
			"injection",
			"Remove persona-switching language from tool-facing content. Descriptions should explain tool functionality, not assign new roles to the model.",
		),

		// PI-005: Instruction extraction
		compilePattern(
			"PI-005",
			"System Prompt Extraction",
			`(repeat\s+(your\s+)?(system\s+prompt|instructions?)|show\s+(me\s+)?(your\s+)?(instructions?|rules?|prompt)|print\s+(your\s+)?prompt|what\s+are\s+your\s+(rules?|instructions?))`,
			models.SeverityHigh,
			"Content attempts to extract the model's system prompt or internal instructions.",
			"injection",
			"Remove extraction-prompting language. Tool descriptions should not instruct the model to reveal its configuration.",
		),

		// PI-006: Delimiter injection
		compilePattern(
			"PI-006",
			"XML/Markdown Delimiter Injection",
			`(<\s*/?\s*(system|instruction|prompt|context|rule)\s*>|\[INST\]|\[\/INST\]|<\|im_start\|>|<\|im_end\|>)`,
			models.SeverityCritical,
			"Content contains structural delimiters used by LLMs to separate system context from user input.",
			"injection",
			"Strip or escape LLM-specific delimiter tokens before including content in tool definitions or responses.",
		),

		// PI-007: Encoding evasion (base64 patterns in descriptions)
		compilePattern(
			"PI-007",
			"Base64 Encoded Payload",
			`[A-Za-z0-9+/]{40,}={0,2}`,
			models.SeverityMedium,
			"Content contains a long base64-encoded string that may hide an encoded injection payload.",
			"injection",
			"Avoid embedding encoded payloads in tool descriptions or parameter defaults. If base64 is legitimately needed, document it explicitly.",
		),

		// PI-008: Character substitution evasion
		compilePattern(
			"PI-008",
			"Character Substitution Evasion",
			`(1gnore|1gn0re|ign0re|pr3tend|forg3t|[i!][gq][mn][o0][r][e3])`,
			models.SeverityHigh,
			"Content uses character substitution to evade injection detection filters.",
			"injection",
			"Remove obfuscated injection language. Character substitution is a known evasion technique for prompt injection filters.",
		),

		// PI-009: Multi-turn manipulation
		compilePattern(
			"PI-009",
			"Conversation History Poisoning",
			`(previous\s+(user|assistant|human)\s+(said|wrote|asked|told)|remember\s+when\s+(i|you|we)\s+(said|told)|earlier\s+in\s+(this|our)\s+conversation)`,
			models.SeverityMedium,
			"Content attempts to manipulate the model by fabricating or referencing earlier conversation turns.",
			"injection",
			"Do not include fabricated conversation history in tool descriptions or prompt templates.",
		),

		// PI-010: Jailbreak trigger phrases
		compilePattern(
			"PI-010",
			"Jailbreak Trigger Phrase",
			`(dan\s+mode|jailbreak|developer\s+mode|unrestricted\s+mode|no\s+restrictions\s+mode|bypass\s+(safety|filter|restriction))`,
			models.SeverityCritical,
			"Content contains known jailbreak trigger phrases that attempt to disable model safety features.",
			"injection",
			"Remove jailbreak language entirely. These phrases signal malicious intent and will be blocked by most model providers.",
		),
	}
}
