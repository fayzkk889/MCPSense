package checks

import (
	"context"
	"fmt"
	"net/url"
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
			findings = append(findings, advisoryFinding(res.Package, v, location))
		}
	}
	return findings
}

func advisoryFinding(pkg cve.Package, v cve.Vuln, location models.Location) models.Finding {
	evidence := &models.AdvisoryEvidence{ID: v.ID, Applicability: "reported_affected", FeedURL: "https://osv.dev/vulnerability/" + url.PathEscape(v.ID)}
	pinNote := ""
	if pkg.Version == "" {
		evidence.Applicability = "version_unresolved"
		pinNote = " The installed version is unresolved; this is a package-level advisory candidate and may not apply. Resolve the installed version before deciding whether it is affected."
	}
	summary := v.Summary
	if summary == "" {
		summary = "See the advisory for details."
	}
	source := "OSV"
	if v.Source != "" {
		source = v.Source + " (reviewed " + v.ReviewedAt + ")"
		evidence.FeedURL = v.Source
	}
	f := models.Finding{ID: "CVE-001", Title: fmt.Sprintf("%s in %q (%s)", v.ID, pkg.Name, pkg.Server),
		Description: fmt.Sprintf("Component %q declares %s%s. Advisory %s from %s: %s%s", pkg.Server, pkg.Name, versionSuffix(pkg.Version), v.ID, source, summary, pinNote),
		Severity:    severityFromCVSS(v.CVSS), Category: models.CategorySecurity, Location: location, Advisory: evidence,
		Remediation: "Review this advisory's package-specific affected and patched branches, deployment prerequisites and required configuration. Resolve and pin an appropriate fixed version, apply the required settings, then retest. Upgrading alone may not remediate the issue."}
	if reviewedApplicabilityConflict(pkg, v.ID) {
		evidence.Applicability = "conflicting_sources"
		evidence.ReviewedURL, evidence.ReviewedAt = tensorlakeAdvisory, "2026-10-30"
		evidence.ReviewNote = "The publisher identifies 0.5.144 as compromised and states 0.5.143 is unaffected by that compromise. OSV reports this exact 0.5.143 declaration as affected. Applicability is unresolved; this is not confirmation of infection or proof of safety."
		f.Confidence = "unresolved_applicability"
		f.Title = fmt.Sprintf("Advisory applicability conflict: %s for %q (%s)", v.ID, pkg.Name, pkg.Server)
		f.Description = fmt.Sprintf("Component %q declares %s%s. %s Publisher review: %s (reviewed %s). Feed evidence: %s. Feed summary: %s", pkg.Server, pkg.Name, versionSuffix(pkg.Version), evidence.ReviewNote, evidence.ReviewedURL, evidence.ReviewedAt, evidence.FeedURL, summary)
		f.Remediation = "Review both cited sources and verify the installed artifact before making a trust decision. The warning and its severity are retained; no advisory or version was silently excluded. Do not infer that other versions or other advisories are cleared."
	}
	return f
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
