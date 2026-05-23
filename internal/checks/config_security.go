package checks

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/fayzkk889/MCPSense/internal/models"
)

// --- SEC-014: STDIO Command Injection in Config ---

// ConfigCommandInjectionCheck detects shell metacharacters and suspicious commands in
// MCP client config files that could achieve RCE when the config is loaded by an IDE.
type ConfigCommandInjectionCheck struct{}

func (c *ConfigCommandInjectionCheck) ID() string              { return "SEC-014" }
func (c *ConfigCommandInjectionCheck) Name() string            { return "Command injection in MCP client config" }
func (c *ConfigCommandInjectionCheck) Category() models.Category { return models.CategorySecurity }

// shellMetacharPattern matches shell metacharacters in command strings.
var shellMetacharPattern = regexp.MustCompile(`[;&|` + "`" + `$(){}]`)

// suspiciousCommands are binaries that should never appear in MCP server configs.
var suspiciousCommands = []string{
	"curl", "wget", "nc", "ncat", "netcat", "bash -c", "sh -c", "cmd /c",
	"powershell -c", "python -c", "python3 -c", "ruby -e", "perl -e", "node -e",
}

func (c *ConfigCommandInjectionCheck) Run(ctx *ScanContext) []models.Finding {
	if ctx.ClientConfig == nil {
		return nil
	}
	var findings []models.Finding
	for serverName, entry := range ctx.ClientConfig.MCPServers {
		// Check the command field
		if shellMetacharPattern.MatchString(entry.Command) {
			findings = append(findings, models.Finding{
				ID:          "SEC-014",
				Title:       fmt.Sprintf("Shell metacharacters in config server %q command", serverName),
				Description: fmt.Sprintf("MCP server entry %q has command %q containing shell metacharacters. This is the exact attack vector used in CVE-2025-6514 and CVE-2026-30615 to achieve RCE via MCP config files.", serverName, entry.Command),
				Severity:    models.SeverityCritical,
				Category:    models.CategorySecurity,
				Location:    models.Location{File: serverName},
				Remediation: "Remove all shell metacharacters from the command field. Use only a direct binary path (e.g., 'npx', 'node', 'python3'). Never use shell-interpreted command strings in MCP configs.",
			})
		}

		// Check args for shell metacharacters
		fullArgs := strings.Join(entry.Args, " ")
		if shellMetacharPattern.MatchString(fullArgs) {
			findings = append(findings, models.Finding{
				ID:          "SEC-014",
				Title:       fmt.Sprintf("Shell metacharacters in config server %q args", serverName),
				Description: fmt.Sprintf("MCP server entry %q has args containing shell metacharacters: %v. Arguments are passed to shell execution by most MCP clients, enabling command injection.", serverName, entry.Args),
				Severity:    models.SeverityCritical,
				Category:    models.CategorySecurity,
				Location:    models.Location{File: serverName},
				Remediation: "Remove shell metacharacters from all arguments. Each argument should be a plain string with no shell interpretation.",
			})
		}

		// Check for suspicious commands
		cmdLower := strings.ToLower(entry.Command + " " + fullArgs)
		for _, suspicious := range suspiciousCommands {
			if strings.Contains(cmdLower, suspicious) {
				findings = append(findings, models.Finding{
					ID:          "SEC-014",
					Title:       fmt.Sprintf("Suspicious command in config server %q", serverName),
					Description: fmt.Sprintf("MCP server entry %q uses %q, which is unusual for a legitimate MCP server and may indicate an attempt to download or execute malicious code.", serverName, suspicious),
					Severity:    models.SeverityHigh,
					Category:    models.CategorySecurity,
					Location:    models.Location{File: serverName},
					Remediation: "Verify this is a legitimate MCP server. Standard MCP servers use 'npx', 'uvx', 'node', 'python', or a direct binary path as their command. Network-fetching commands like curl/wget in a config are a red flag.",
				})
				break
			}
		}
	}
	return findings
}

// --- SEC-015: Sensitive Environment Variable Leakage ---

// ConfigEnvLeakageCheck flags config entries that pass sensitive environment variables to MCP servers.
type ConfigEnvLeakageCheck struct{}

func (c *ConfigEnvLeakageCheck) ID() string              { return "SEC-015" }
func (c *ConfigEnvLeakageCheck) Name() string            { return "Sensitive env vars passed to MCP server" }
func (c *ConfigEnvLeakageCheck) Category() models.Category { return models.CategorySecurity }

// sensitiveEnvPrefixes lists env var name prefixes that indicate secrets.
var sensitiveEnvPrefixes = []string{
	"AWS_SECRET", "AWS_SESSION", "GITHUB_TOKEN", "GITLAB_TOKEN", "GH_TOKEN",
	"OPENAI_API", "ANTHROPIC_API", "GOOGLE_API", "AZURE_", "DATABASE_URL",
	"DB_PASSWORD", "PRIVATE_KEY", "SECRET_KEY", "JWT_SECRET", "ENCRYPTION_KEY",
	"STRIPE_SECRET", "SENDGRID_API", "TWILIO_AUTH", "SLACK_TOKEN", "DISCORD_TOKEN",
}

// sensitiveEnvExact lists exact env var names that are secrets.
var sensitiveEnvExact = []string{
	"PASSWORD", "PASSWD", "SECRET", "TOKEN", "PRIVATE_KEY",
}

func (c *ConfigEnvLeakageCheck) Run(ctx *ScanContext) []models.Finding {
	if ctx.ClientConfig == nil {
		return nil
	}
	var findings []models.Finding
	for serverName, entry := range ctx.ClientConfig.MCPServers {
		for envName := range entry.Env {
			upper := strings.ToUpper(envName)
			isSensitive := false
			for _, prefix := range sensitiveEnvPrefixes {
				if strings.HasPrefix(upper, prefix) {
					isSensitive = true
					break
				}
			}
			if !isSensitive {
				for _, exact := range sensitiveEnvExact {
					if upper == exact || strings.HasSuffix(upper, "_"+exact) {
						isSensitive = true
						break
					}
				}
			}
			if isSensitive {
				findings = append(findings, models.Finding{
					ID:          "SEC-015",
					Title:       fmt.Sprintf("Sensitive env var %q passed to MCP server %q", envName, serverName),
					Description: fmt.Sprintf("MCP server %q receives environment variable %q which appears to contain sensitive credentials. If this server is compromised or malicious, these credentials will be exposed.", serverName, envName),
					Severity:    models.SeverityMedium,
					Category:    models.CategorySecurity,
					Location:    models.Location{File: serverName},
					Remediation: "Only pass the minimum necessary environment variables to MCP servers. Use scoped, server-specific API keys rather than sharing broad credentials. Consider using a secrets manager instead of environment variables.",
				})
			}
		}
	}
	return findings
}

// --- SEC-016: Unverified / Unpinned Server Sources ---

// ConfigUnverifiedSourceCheck flags MCP server entries that use unpinned or unverified package sources.
type ConfigUnverifiedSourceCheck struct{}

func (c *ConfigUnverifiedSourceCheck) ID() string              { return "SEC-016" }
func (c *ConfigUnverifiedSourceCheck) Name() string            { return "Unverified MCP server source" }
func (c *ConfigUnverifiedSourceCheck) Category() models.Category { return models.CategorySecurity }

func (c *ConfigUnverifiedSourceCheck) Run(ctx *ScanContext) []models.Finding {
	if ctx.ClientConfig == nil {
		return nil
	}
	var findings []models.Finding
	for serverName, entry := range ctx.ClientConfig.MCPServers {
		allArgs := strings.Join(entry.Args, " ")
		cmdLower := strings.ToLower(entry.Command)

		// Check for npx without version pinning (-y flag means auto-install without confirmation)
		if cmdLower == "npx" {
			hasAutoYes := false
			for _, arg := range entry.Args {
				if arg == "-y" || arg == "--yes" {
					hasAutoYes = true
					break
				}
			}
			// Check if the package has a version specifier (@version)
			hasVersion := false
			for _, arg := range entry.Args {
				if !strings.HasPrefix(arg, "-") && strings.Contains(arg, "@") && !strings.HasPrefix(arg, "@") {
					// package@version format (not @scoped/package)
					hasVersion = true
					break
				}
				if strings.HasPrefix(arg, "@") && strings.Count(arg, "@") >= 2 {
					// @scope/package@version
					hasVersion = true
					break
				}
			}
			if hasAutoYes && !hasVersion {
				findings = append(findings, models.Finding{
					ID:          "SEC-016",
					Title:       fmt.Sprintf("Unpinned npx package in config server %q", serverName),
					Description: fmt.Sprintf("MCP server %q uses 'npx -y' to auto-install a package without version pinning. A supply chain attack (typosquatting or package takeover) could install malicious code.", serverName),
					Severity:    models.SeverityMedium,
					Category:    models.CategorySecurity,
					Location:    models.Location{File: serverName},
					Remediation: "Pin the package to a specific version (e.g., 'npx -y @scope/package@1.2.3') or use 'npm install' with a lockfile instead of npx.",
				})
			}
		}

		// Check for HTTP (non-HTTPS) URLs in args or URL field
		if strings.Contains(allArgs, "http://") || strings.HasPrefix(entry.URL, "http://") {
			findings = append(findings, models.Finding{
				ID:          "SEC-016",
				Title:       fmt.Sprintf("Insecure HTTP URL in config server %q", serverName),
				Description: fmt.Sprintf("MCP server %q references an HTTP (not HTTPS) URL. MCP traffic over unencrypted HTTP is vulnerable to man-in-the-middle attacks.", serverName),
				Severity:    models.SeverityHigh,
				Category:    models.CategorySecurity,
				Location:    models.Location{File: serverName},
				Remediation: "Use HTTPS for all MCP server URLs. The MCP spec requires TLS for all remote connections.",
			})
		}
	}
	return findings
}
