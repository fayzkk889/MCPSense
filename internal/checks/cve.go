package checks

import (
	"context"
	"fmt"
	"strings"

	"github.com/fayzkk889/MCPSense/internal/cve"
	"github.com/fayzkk889/MCPSense/internal/inventory"
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
	if c.Disabled || (ctx.ClientConfig == nil && ctx.Dependencies == nil) {
		ctx.AdvisoryState = "skipped"
		return nil
	}

	pkgs := []cve.Package{}
	if ctx.ClientConfig != nil {
		pkgs = extractPackages(ctx.ClientConfig)
	}
	ctx.AdvisoryScope = "recognized_launch_packages_osv_plus_vendor_snapshot_" + vendorAdvisoryDate
	if ctx.Dependencies != nil {
		declared, err := inventory.Packages(ctx.Dependencies)
		if err != nil {
			ctx.AdvisoryState = "failed"
			ctx.Errors = append(ctx.Errors, err)
			return nil
		}
		pkgs = append(pkgs, declared...)
		ctx.AdvisoryScope = "explicit_npm_lock_and_recognized_launch_packages_osv_plus_vendor_snapshot_" + vendorAdvisoryDate
	}
	if len(pkgs) == 0 {
		ctx.AdvisoryState = "not_applicable"
		return nil
	}

	client := cve.NewClient()
	cve.PruneCache()
	parent := ctx.Context
	if parent == nil {
		parent = context.Background()
	}
	results, ok := client.CheckAllContext(parent, pkgs)
	if !ok {
		ctx.AdvisoryState = "failed"
		ctx.Errors = append(ctx.Errors, fmt.Errorf("advisory coverage incomplete: lookup failed, data stale, cancellation or scan limits exceeded; retry, reduce scope or explicitly use --no-cve"))
		return nil
	}
	ctx.AdvisoryState = "completed"
	results = mergeAdvisoryResults(results, reviewedVendorResults(pkgs))
	count := 0
	for _, res := range results {
		count += len(res.Vulns)
	}
	if count > cve.MaxMatches {
		ctx.AdvisoryState = "failed"
		ctx.Errors = append(ctx.Errors, fmt.Errorf("advisory matches exceed %d finding limit; reduce scan scope", cve.MaxMatches))
		return nil
	}

	var findings []models.Finding
	for _, res := range results {
		location := models.Location{File: res.Package.Server}
		if res.Package.File != "" {
			location = models.Location{File: res.Package.File, ToolName: res.Package.Server}
		}
		for _, v := range res.Vulns {
			sev := severityFromCVSS(v.CVSS)
			pinNote := ""
			if res.Package.Version == "" {
				pinNote = " The installed version is unresolved; this is a package-level advisory candidate and may not apply. Resolve the installed version before deciding whether it is affected."
			}
			remediation := "Review this advisory's package-specific affected and patched branches, deployment prerequisites and required configuration. Resolve and pin an appropriate fixed version, apply the required settings, then retest. Upgrading alone may not remediate the issue."
			summary := v.Summary
			if summary == "" {
				summary = "See the advisory for details."
			}
			source := "OSV"
			if v.Source != "" {
				source = v.Source + " (reviewed " + v.ReviewedAt + ")"
			}
			findings = append(findings, models.Finding{
				ID:          "CVE-001",
				Title:       fmt.Sprintf("%s in %q (%s)", v.ID, res.Package.Name, res.Package.Server),
				Description: fmt.Sprintf("Component %q declares %s%s. Advisory %s from %s: %s%s", res.Package.Server, res.Package.Name, versionSuffix(res.Package.Version), v.ID, source, summary, pinNote),
				Severity:    sev,
				Category:    models.CategorySecurity,
				Location:    location,
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
