package checks

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/fayzkk889/MCPSense/internal/cve"
)

// Deliberately small, reviewed supplement, not a complete vulnerability database.
// Verified 2026-10-23 against the publisher's bulletin and repository advisory.
// Changing this production source also changes the detector identity.
const vendorAdvisoryDate = "2026-10-23"
const postgresAdvisory = "https://github.com/awslabs/mcp/security/advisories/GHSA-fph8-pg5w-78fv"

var pypiNameSeparators = regexp.MustCompile(`[._-]+`)

func reviewedVendorResults(pkgs []cve.Package) []cve.Result {
	var results []cve.Result
	for _, pkg := range pkgs {
		name := pypiNameSeparators.ReplaceAllString(strings.ToLower(pkg.Name), "-")
		if pkg.Ecosystem != "PyPI" || name != "awslabs-postgres-mcp-server" {
			continue
		}
		affected, comparable := stableVersionBefore(pkg.Version, "1.1.7")
		if comparable && !affected {
			continue
		}
		summary := "AWS reports a read-only SQL enforcement bypass before 1.1.7. In self-managed PostgreSQL deployments using PG_WIRE_PROTOCOL with superuser or pg_execute_server_program privileges, crafted SQL can reach OS command execution. Database-enforced least privilege bounds this risk. Deployment prerequisites were not assessed."
		if !comparable {
			summary = "Version applicability is unresolved; review this advisory candidate. " + summary
		}
		results = append(results, cve.Result{Package: pkg, Vulns: []cve.Vuln{{ID: "GHSA-fph8-pg5w-78fv", Summary: summary, CVSS: 9.6, Source: postgresAdvisory, ReviewedAt: vendorAdvisoryDate}}})
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
		return pkg.Server + "\x00" + pkg.Ecosystem + "\x00" + pkg.Name + "\x00" + pkg.Version + "\x00" + id
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
