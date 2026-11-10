package checks

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/fayzkk889/MCPSense/internal/cve"
)

// Deliberately small, reviewed supplement, not a complete vulnerability database.
// Snapshot updated 2026-11-10; individual records retain their review dates.
// Changing this production source also changes the detector identity.
const vendorAdvisoryDate = "2026-11-10"
const postgresAdvisory = "https://github.com/awslabs/mcp/security/advisories/GHSA-fph8-pg5w-78fv"
const postgresReviewedAt = "2026-10-23"
const awsAPIAdvisory = "https://github.com/awslabs/mcp/security/advisories/GHSA-4prq-p2x5-w9fh"
const awsServerlessAdvisory = "https://github.com/awslabs/mcp/security/advisories/GHSA-r6mm-377j-qg8m"
const tensorlakeAdvisory = "https://github.com/tensorlakeai/tensorlake/security/advisories/GHSA-8g63-53c9-65j2"

// Exact reviewed disagreement, not an allowlist or a claim about other
// versions/advisories. The feed warning is retained at its original severity.
func reviewedApplicabilityConflict(pkg cve.Package, id string) bool {
	return pkg.Ecosystem == "npm" && pkg.Name == "tensorlake" && pkg.Version == "0.5.143" &&
		(id == "MAL-2026-17650" || id == "GHSA-rqxj-g25x-4v9v")
}

var pypiNameSeparators = regexp.MustCompile(`[._-]+`)

func reviewedVendorResults(pkgs []cve.Package) []cve.Result {
	var results []cve.Result
	for _, pkg := range pkgs {
		name := pypiNameSeparators.ReplaceAllString(strings.ToLower(pkg.Name), "-")
		if pkg.Ecosystem != "PyPI" {
			continue
		}
		var id, fixed, introduced, source, reviewed, summary string
		var score float64
		switch name {
		case "awslabs-postgres-mcp-server":
			id, fixed, source, reviewed, score = "GHSA-fph8-pg5w-78fv", "1.1.7", postgresAdvisory, postgresReviewedAt, 9.6
			summary = "AWS reports a read-only SQL enforcement bypass before 1.1.7. In self-managed PostgreSQL deployments using PG_WIRE_PROTOCOL with superuser or pg_execute_server_program privileges, crafted SQL can reach OS command execution. Database-enforced least privilege bounds this risk. Deployment prerequisites were not assessed."
		case "awslabs-aws-api-mcp-server":
			id, introduced, fixed, source, reviewed, score = "GHSA-4prq-p2x5-w9fh", "1.3.0", "1.6.0", awsAPIAdvisory, "2026-11-10", 7.3
			summary = "AWS reports missing OAuth token audience validation in versions >=1.3.0 and <1.6.0. Only streamable-http deployments using OAuth are affected: a token for another application at the configured identity provider may authorize AWS calls with the host's credentials. Upgrade to 1.6.0 or later and configure AUTH_AUDIENCE or AUTH_CLIENT_ID as appropriate for the identity provider. The default stdio transport is not affected. Deployment prerequisites were not assessed."
		case "awslabs-aws-serverless-mcp-server":
			id, fixed, source, reviewed, score = "GHSA-r6mm-377j-qg8m", "0.2.1", awsServerlessAdvisory, "2026-11-10", 6.1
			summary = "AWS reports path traversal in deployment-status project names before 0.2.1. An actor able to influence the agent can read JSON files outside the intended status directory using traversal sequences or absolute paths. Creating or overwriting outside JSON files additionally requires --enable-write. Upgrade to 0.2.1 or later. Deployment prerequisites were not assessed."
		default:
			continue
		}
		affected, comparable := stableVersionBefore(pkg.Version, fixed)
		if comparable && !affected {
			continue
		}
		if introduced != "" && comparable {
			if before, _ := stableVersionBefore(pkg.Version, introduced); before {
				continue
			}
		}
		applicability := ""
		if !comparable {
			applicability = "version_unresolved"
			summary = "Version applicability is unresolved; review this advisory candidate. " + summary
		}
		results = append(results, cve.Result{Package: pkg, Vulns: []cve.Vuln{{ID: id, Summary: summary, CVSS: score, Source: source, ReviewedAt: reviewed, FixedVersion: fixed, Applicability: applicability}}})
	}
	return results
}

// Compare only stable three-component release numbers. Do not guess PEP 440
// pre/dev/post/epoch/local ordering; those remain explicit advisory candidates.
func stableVersionBefore(version, fixed string) (bool, bool) {
	parse := func(value string) ([3]uint64, bool) {
		var out [3]uint64
		parts := strings.Split(value, ".")
		if len(parts) != 3 {
			return out, false
		}
		for i, part := range parts {
			if part == "" {
				return out, false
			}
			for _, ch := range part {
				if ch < '0' || ch > '9' {
					return out, false
				}
			}
			n, err := strconv.ParseUint(part, 10, 64)
			if err != nil {
				return out, false
			}
			out[i] = n
		}
		return out, true
	}
	a, ok := parse(version)
	if !ok {
		return false, false
	}
	b, ok := parse(fixed)
	if !ok {
		return false, false
	}
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i], true
		}
	}
	return false, true
}

func mergeAdvisoryResults(results, supplemental []cve.Result) []cve.Result {
	type position struct{ result, vuln int }
	seen := map[string]position{}
	identity := func(pkg cve.Package, id string) string {
		if id == "CVE-2026-87911" {
			id = "GHSA-fph8-pg5w-78fv"
		}
		if id == "CVE-2026-115413" {
			id = "GHSA-4prq-p2x5-w9fh"
		}
		if id == "CVE-2026-116635" {
			id = "GHSA-r6mm-377j-qg8m"
		}
		return pkg.File + "\x00" + pkg.Server + "\x00" + pkg.Ecosystem + "\x00" + pkg.Name + "\x00" + pkg.Version + "\x00" + id
	}
	for i, result := range results {
		for j, vuln := range result.Vulns {
			seen[identity(result.Package, vuln.ID)] = position{i, j}
		}
	}
	for _, result := range supplemental {
		for _, vuln := range result.Vulns {
			key := identity(result.Package, vuln.ID)
			if at, ok := seen[key]; ok {
				// Keep the publisher prerequisites and provenance when the feed
				// starts indexing this same advisory (under either known ID).
				results[at.result].Vulns[at.vuln] = vuln
			} else {
				results = append(results, cve.Result{Package: result.Package, Vulns: []cve.Vuln{vuln}})
				seen[key] = position{len(results) - 1, 0}
			}
		}
	}
	return results
}
