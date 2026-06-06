package checks

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/fayzkk889/MCPSense/internal/models"
)

// --- SKILL-001: Prompt injection / poisoning in skill instructions ---

// SkillInjectionCheck runs the prompt-injection pattern engine against skill files.
// Skills deliver instructions into the agent's reasoning loop, so the same injection
// patterns that apply to tool descriptions apply here.
type SkillInjectionCheck struct{}

func (c *SkillInjectionCheck) ID() string                { return "SKILL-001" }
func (c *SkillInjectionCheck) Name() string              { return "Prompt injection in agent skill" }
func (c *SkillInjectionCheck) Category() models.Category { return models.CategorySecurity }

func (c *SkillInjectionCheck) Run(ctx *ScanContext) []models.Finding {
	if len(ctx.SkillFiles) == 0 || ctx.Patterns == nil {
		return nil
	}
	var findings []models.Finding
	for path, content := range ctx.SkillFiles {
		matches := ctx.Patterns.ScanDescriptions(content)
		for _, m := range matches {
			findings = append(findings, models.Finding{
				ID:          "SKILL-001",
				Title:       fmt.Sprintf("Prompt injection in skill file (%s)", m.PatternName),
				Description: fmt.Sprintf("Skill file %q contains content matching injection pattern %s: %q. Skills are loaded directly into the agent's instruction context, so injected directives here hijack the agent's reasoning the same way a poisoned tool description does.", path, m.PatternID, truncateSkill(m.MatchedText, 120)),
				Severity:    m.Severity,
				Category:    models.CategorySecurity,
				Location:    models.Location{File: path},
				Remediation: m.Remediation,
			})
		}
	}
	return findings
}

// --- SKILL-002: Overbroad tool grants in skill ---

// SkillToolGrantCheck flags skills that grant excessively broad tool access.
type SkillToolGrantCheck struct{}

func (c *SkillToolGrantCheck) ID() string                { return "SKILL-002" }
func (c *SkillToolGrantCheck) Name() string              { return "Overbroad tool grant in agent skill" }
func (c *SkillToolGrantCheck) Category() models.Category { return models.CategorySecurity }

var (
	// allowed-tools frontmatter with a wildcard, or Bash with no command restriction.
	overbroadGrantPattern = regexp.MustCompile(`(?i)(allowed[-_]?tools\s*:\s*.*(\*|all)|bash\s*\(\s*\*\s*\)|--dangerously-skip-permissions|allow[-_]?all[-_]?tools)`)
)

func (c *SkillToolGrantCheck) Run(ctx *ScanContext) []models.Finding {
	if len(ctx.SkillFiles) == 0 {
		return nil
	}
	var findings []models.Finding
	for path, content := range ctx.SkillFiles {
		if loc := overbroadGrantPattern.FindString(content); loc != "" {
			findings = append(findings, models.Finding{
				ID:          "SKILL-002",
				Title:       fmt.Sprintf("Overbroad tool grant in skill file %q", path),
				Description: fmt.Sprintf("Skill file %q grants broad or unrestricted tool access (matched: %q). A skill with wildcard tool permissions or skipped permission checks can perform any action the agent is capable of, far beyond what the skill needs.", path, strings.TrimSpace(loc)),
				Severity:    models.SeverityHigh,
				Category:    models.CategorySecurity,
				Location:    models.Location{File: path},
				Remediation: "Restrict the skill's tool grants to the minimum set it actually needs. Avoid wildcards in allowed-tools, never use --dangerously-skip-permissions in a shared skill, and scope Bash access to specific commands.",
			})
		}
	}
	return findings
}

// --- SKILL-003: Sensitive file or credential reference in skill ---

// SkillSensitiveRefCheck flags skills that reference sensitive files or credentials.
type SkillSensitiveRefCheck struct{}

func (c *SkillSensitiveRefCheck) ID() string                { return "SKILL-003" }
func (c *SkillSensitiveRefCheck) Name() string              { return "Sensitive file reference in agent skill" }
func (c *SkillSensitiveRefCheck) Category() models.Category { return models.CategorySecurity }

var sensitiveRefPattern = regexp.MustCompile(`(?i)(\.env\b|id_rsa|\.ssh/|\.aws/credentials|\.git-credentials|\.npmrc|/etc/passwd|/etc/shadow|private[_-]?key|secrets?\.(json|ya?ml|txt))`)

func (c *SkillSensitiveRefCheck) Run(ctx *ScanContext) []models.Finding {
	if len(ctx.SkillFiles) == 0 {
		return nil
	}
	var findings []models.Finding
	for path, content := range ctx.SkillFiles {
		if match := sensitiveRefPattern.FindString(content); match != "" {
			findings = append(findings, models.Finding{
				ID:          "SKILL-003",
				Title:       fmt.Sprintf("Sensitive file reference in skill file %q", path),
				Description: fmt.Sprintf("Skill file %q references a sensitive file or credential location (matched: %q). A skill that instructs the agent to read secrets can exfiltrate them through any connected tool.", path, match),
				Severity:    models.SeverityHigh,
				Category:    models.CategorySecurity,
				Location:    models.Location{File: path},
				Remediation: "Skills should never instruct the agent to read credential files, SSH keys, or environment secrets. Remove the reference, or if the skill legitimately needs a secret, supply it through a scoped, audited mechanism rather than direct file reads.",
			})
		}
	}
	return findings
}

func truncateSkill(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
