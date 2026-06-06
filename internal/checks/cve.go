package checks

import (
	"fmt"
	"strings"

	"github.com/fayzkk889/MCPSense/internal/cve"
	"github.com/fayzkk889/MCPSense/internal/models"
)

// DependencyCVECheck cross-references MCP server package dependencies against OSV.dev.
type DependencyCVECheck struct {
	// Disabled is set true by the scanner when --no-cve or --offline is used.
	Disabled bool
}

func (c *DependencyCVECheck) ID() string                { return "CVE-001" }
func (c *DependencyCVECheck) Name() string              { return "Known CVE in MCP server dependency" }
func (c *DependencyCVECheck) Category() models.Category { return models.CategorySecurity }

func (c *DependencyCVECheck) Run(ctx *ScanContext) []models.Finding {
	if c.Disabled || ctx.ClientConfig == nil {
		return nil
	}

	pkgs := extractPackages(ctx.ClientConfig)
	if len(pkgs) == 0 {
		return nil
	}

	client := cve.NewClient()
	cve.PruneCache()
	results, ok := client.CheckAll(pkgs)
	if !ok {
		// Offline or OSV unreachable. Skip silently; the scanner prints one note.
		return nil
	}

	var findings []models.Finding
	for _, res := range results {
		for _, v := range res.Vulns {
			sev := severityFromCVSS(v.CVSS)
			pinNote := ""
			if res.Package.Version == "" {
				pinNote = " This package is also unpinned, so you may already be installing a vulnerable version."
			}
			remediation := "Review this CVE and upgrade the package."
			if v.FixedVersion != "" {
				remediation = fmt.Sprintf("Upgrade %s to %s or later (pin the version in your config).", res.Package.Name, v.FixedVersion)
			}
			summary := v.Summary
			if summary == "" {
				summary = "See the advisory for details."
			}
			findings = append(findings, models.Finding{
				ID:          "CVE-001",
				Title:       fmt.Sprintf("%s in %q (%s)", v.ID, res.Package.Name, res.Package.Server),
				Description: fmt.Sprintf("MCP server %q depends on %s%s, which has a known vulnerability %s: %s%s", res.Package.Server, res.Package.Name, versionSuffix(res.Package.Version), v.ID, summary, pinNote),
				Severity:    sev,
				Category:    models.CategorySecurity,
				Location:    models.Location{File: res.Package.Server},
				Remediation: remediation,
			})
		}
	}
	return findings
}

func versionSuffix(version string) string {
	if version == "" {
		return ""
	}
	return "@" + version
}

func severityFromCVSS(score float64) models.Severity {
	switch {
	case score >= 9.0:
		return models.SeverityCritical
	case score >= 7.0:
		return models.SeverityHigh
	case score >= 4.0:
		return models.SeverityMedium
	case score > 0:
		return models.SeverityLow
	default:
		// No numeric score available, but a CVE exists. Default to High to be safe.
		return models.SeverityHigh
	}
}

// extractPackages pulls package names, versions, and ecosystems from the client config.
// Mirrors the npx parsing in ConfigUnverifiedSourceCheck (SEC-016).
func extractPackages(config *models.MCPClientConfig) []cve.Package {
	var pkgs []cve.Package
	for serverName, entry := range config.MCPServers {
		eco := cve.EcosystemForCommand(entry.Command)
		if eco == "" {
			continue
		}
		// Find the package argument: the first non-flag argument.
		for _, arg := range entry.Args {
			if strings.HasPrefix(arg, "-") {
				continue // skip flags like -y, --yes
			}
			name, version := splitPackageVersion(arg)
			if name == "" {
				continue
			}
			pkgs = append(pkgs, cve.Package{
				Name:      name,
				Version:   version,
				Ecosystem: eco,
				Server:    serverName,
			})
			break // first package arg only
		}
	}
	return pkgs
}

// splitPackageVersion splits "pkg@1.2.3" or "@scope/pkg@1.2.3" into name and version.
func splitPackageVersion(arg string) (name, version string) {
	if arg == "" {
		return "", ""
	}
	if strings.HasPrefix(arg, "@") {
		// scoped: @scope/pkg or @scope/pkg@version
		idx := strings.LastIndex(arg, "@")
		if idx > 0 { // there is a second @, meaning a version
			return arg[:idx], arg[idx+1:]
		}
		return arg, "" // just @scope/pkg, no version
	}
	// unscoped: pkg or pkg@version
	if idx := strings.LastIndex(arg, "@"); idx > 0 {
		return arg[:idx], arg[idx+1:]
	}
	return arg, ""
}
