package checks

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fayzkk889/MCPSense/internal/cve"
	"github.com/fayzkk889/MCPSense/internal/models"
)

func TestVendorSupplementAffectedFixedAndUnknown(t *testing.T) {
	for _, tc := range []struct {
		version         string
		want, candidate bool
	}{
		{"0.1.0", true, false}, {"1.1.6", true, false}, {"1.1.7", false, false}, {"1.1.10", false, false}, {"1.2.0", false, false}, {"2.0.0", false, false}, {"", true, true}, {"1.1.7rc1", true, true}, {"999999999999999999999.0.0", true, true},
	} {
		pkg := cve.Package{Name: "awslabs.postgres-mcp-server", Version: tc.version, Ecosystem: "PyPI", Server: "fixture"}
		r := reviewedVendorResults([]cve.Package{pkg})
		if (len(r) > 0) != tc.want {
			t.Fatalf("wrong applicability for %s: %+v", tc.version, r)
		}
		if len(r) > 0 {
			v := r[0].Vulns[0]
			if v.Source != postgresAdvisory || v.ReviewedAt != postgresReviewedAt || strings.Contains(v.Summary, "unresolved") != tc.candidate {
				t.Fatalf("missing evidence/applicability: %+v", v)
			}
		}
	}
	for _, pkg := range []cve.Package{{Name: "other", Version: "1.0.0", Ecosystem: "PyPI"}, {Name: "awslabs.postgres-mcp-server", Version: "1.0.0", Ecosystem: "npm"}} {
		if len(reviewedVendorResults([]cve.Package{pkg})) != 0 {
			t.Fatal("unrelated package matched")
		}
	}
}

func TestVendorAdvisorySurvivesAnEmptySuccessfulOSVLookup(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	dir := filepath.Join(home, ".mcpsense", "cve-cache")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"1.1.6", "1.1.7"} {
		key := fmt.Sprintf("%x.json", sha256.Sum256([]byte("PyPI|awslabs.postgres-mcp-server|"+version)))
		data, err := json.Marshal(map[string]interface{}{"cache_version": 2, "fetched_at": time.Now().UTC(), "vulns": []interface{}{}})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, key), data, 0600); err != nil {
			t.Fatal(err)
		}
		ctx := newTestCtx()
		ctx.ClientConfig = &models.MCPClientConfig{MCPServers: map[string]models.MCPServerEntry{"postgres": {Command: "uvx", Args: []string{"--from", "awslabs.postgres-mcp-server==" + version, "awslabs.postgres-mcp-server"}}}}
		fs := (&DependencyCVECheck{}).Run(ctx)
		if len(ctx.Errors) != 0 || ctx.AdvisoryState != "completed" || !strings.Contains(ctx.AdvisoryScope, vendorAdvisoryDate) {
			t.Fatalf("incomplete advisory phase: %+v", ctx.Errors)
		}
		if version == "1.1.7" {
			if len(fs) != 0 {
				t.Fatalf("fixed package matched: %+v", fs)
			}
			continue
		}
		if len(fs) != 1 || !strings.Contains(fs[0].Description, postgresAdvisory) || !strings.Contains(fs[0].Description, "Deployment prerequisites were not assessed") || !strings.Contains(fs[0].Remediation, "required configuration") {
			t.Fatalf("lost vendor evidence/conditions: %+v", fs)
		}
		ctx.Errors = nil
		if got := (&DependencyCVECheck{Disabled: true}).Run(ctx); len(got) != 0 || ctx.AdvisoryState != "skipped" {
			t.Fatal("explicit advisory disable was not respected")
		}
	}
}

func TestSupplementPreservesOtherServersAndAvoidsDuplicateAdvisories(t *testing.T) {
	a := cve.Package{Name: "awslabs.postgres-mcp-server", Version: "1.1.6", Ecosystem: "PyPI", Server: "first"}
	b := a
	b.Server = "second"
	for _, id := range []string{"GHSA-fph8-pg5w-78fv", "CVE-2026-87911"} {
		remote := []cve.Result{{Package: a, Vulns: []cve.Vuln{{ID: id}}}}
		merged := mergeAdvisoryResults(remote, reviewedVendorResults([]cve.Package{a, b}))
		if len(merged) != 2 || len(merged[0].Vulns) != 1 || merged[1].Package.Server != "second" || merged[0].Vulns[0].Source != postgresAdvisory || !strings.Contains(merged[0].Vulns[0].Summary, "Deployment prerequisites") {
			t.Fatalf("wrong merge or lost provenance: %+v", merged)
		}
	}
	repeated := reviewedVendorResults([]cve.Package{a})
	repeated[0].Vulns = append(repeated[0].Vulns, repeated[0].Vulns[0])
	if merged := mergeAdvisoryResults(nil, repeated); len(merged) != 1 || len(merged[0].Vulns) != 1 {
		t.Fatalf("repeated supplemental record was counted twice: %+v", merged)
	}
	declared := a
	declared.File = "selected-lock.json"
	if merged := mergeAdvisoryResults(reviewedVendorResults([]cve.Package{a}), reviewedVendorResults([]cve.Package{declared})); len(merged) != 2 {
		t.Fatal("inventory and launch provenance collapsed")
	}
}

func TestAWSAPIAudienceAdvisoryRangeProvenanceAndFeedAliases(t *testing.T) {
	for _, tc := range []struct {
		version         string
		want, candidate bool
	}{
		{"1.2.9", false, false}, {"1.3.0", true, false}, {"1.5.9", true, false}, {"1.6.0", false, false}, {"2.0.0", false, false},
		{"", true, true}, {"1.6.0rc1", true, true}, {"1.6.0.post1", true, true},
	} {
		pkg := cve.Package{Name: "AWSLABS_aws-api.mcp-server", Version: tc.version, Ecosystem: "PyPI", Server: "api"}
		results := reviewedVendorResults([]cve.Package{pkg})
		if (len(results) > 0) != tc.want {
			t.Fatalf("wrong range for %s: %+v", tc.version, results)
		}
		if !tc.want {
			continue
		}
		v := results[0].Vulns[0]
		if v.ID != "GHSA-4prq-p2x5-w9fh" || v.Source != awsAPIAdvisory || v.ReviewedAt != "2026-11-10" || v.FixedVersion != "1.6.0" || strings.Contains(v.Summary, "unresolved") != tc.candidate {
			t.Fatalf("lost applicability: %+v", v)
		}
		finding := advisoryFinding(pkg, v, models.Location{})
		if tc.candidate && (finding.Advisory.Applicability != "version_unresolved" || finding.Confidence != "unresolved_applicability") {
			t.Fatalf("unresolved version incorrectly claimed affected: %+v", finding)
		}
		if !tc.candidate && finding.Advisory.Applicability != "reported_affected" {
			t.Fatal("stable affected version lost applicability")
		}
		for _, required := range []string{"streamable-http", "OAuth", "AUTH_AUDIENCE", "AUTH_CLIENT_ID", "stdio transport is not affected", "Deployment prerequisites were not assessed"} {
			if !strings.Contains(v.Summary, required) {
				t.Fatal("lost deployment conditions: " + required)
			}
		}
		for _, id := range []string{v.ID, "CVE-2026-115413"} {
			merged := mergeAdvisoryResults([]cve.Result{{Package: pkg, Vulns: []cve.Vuln{{ID: id}}}}, results)
			if len(merged) != 1 || len(merged[0].Vulns) != 1 || merged[0].Vulns[0].Source != awsAPIAdvisory {
				t.Fatal("vendor and feed alias duplicated or lost source")
			}
		}
	}
	if len(reviewedVendorResults([]cve.Package{{Name: "awslabs.aws-api-mcp-server", Version: "1.5.0", Ecosystem: "npm"}})) != 0 {
		t.Fatal("wrong ecosystem matched")
	}
}

func TestAWSAPIAdvisorySurvivesEmptyFeedWithoutClaimingRuntimeValidation(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	dir := filepath.Join(home, ".mcpsense", "cve-cache")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"1.2.9", "1.3.0", "1.5.0", "1.6.0"} {
		key := fmt.Sprintf("%x.json", sha256.Sum256([]byte("PyPI|awslabs.aws-api-mcp-server|"+version)))
		data, _ := json.Marshal(map[string]interface{}{"cache_version": 2, "fetched_at": time.Now().UTC(), "vulns": []interface{}{}})
		if err := os.WriteFile(filepath.Join(dir, key), data, 0600); err != nil {
			t.Fatal(err)
		}
		ctx := newTestCtx()
		ctx.ClientConfig = &models.MCPClientConfig{MCPServers: map[string]models.MCPServerEntry{"api": {Command: "uvx", Args: []string{"--from", "awslabs.aws-api-mcp-server==" + version, "awslabs.aws-api-mcp-server"}}}}
		findings := (&DependencyCVECheck{}).Run(ctx)
		want := version == "1.3.0" || version == "1.5.0"
		if (len(findings) > 0) != want || len(ctx.Errors) > 0 || ctx.AdvisoryState != "completed" {
			t.Fatalf("wrong empty-feed result for %s: %+v %+v", version, findings, ctx.Errors)
		}
		if want && (!strings.Contains(findings[0].Description, awsAPIAdvisory) || !strings.Contains(findings[0].Description, "Deployment prerequisites were not assessed")) {
			t.Fatal("lost source or runtime limitation")
		}
	}
}

func TestAWSServerlessTraversalAdvisory(t *testing.T) {
	for _, tc := range []struct {
		version         string
		want, candidate bool
	}{
		{"0.0.0", true, false}, {"0.2.0", true, false}, {"0.2.1", false, false}, {"1.0.0", false, false}, {"", true, true}, {"0.2.1rc1", true, true},
	} {
		pkg := cve.Package{Name: "awslabs.aws-serverless-mcp-server", Version: tc.version, Ecosystem: "PyPI", Server: "fixture"}
		results := reviewedVendorResults([]cve.Package{pkg})
		if (len(results) > 0) != tc.want {
			t.Fatalf("wrong applicability for %s: %+v", tc.version, results)
		}
		if !tc.want {
			continue
		}
		v := results[0].Vulns[0]
		if v.Source != awsServerlessAdvisory || v.FixedVersion != "0.2.1" || v.ReviewedAt != "2026-11-10" || v.CVSS != 6.1 || strings.Contains(v.Summary, "unresolved") != tc.candidate {
			t.Fatalf("lost vendor evidence: %+v", v)
		}
		if !strings.Contains(v.Summary, "--enable-write") || !strings.Contains(v.Summary, "Deployment prerequisites were not assessed") {
			t.Fatal("lost write prerequisite or coverage limitation")
		}
		f := advisoryFinding(pkg, v, models.Location{})
		if tc.candidate && f.Advisory.Applicability != "version_unresolved" {
			t.Fatal("unknown version asserted affected")
		}
		merged := mergeAdvisoryResults([]cve.Result{{Package: pkg, Vulns: []cve.Vuln{{ID: "CVE-2026-116635"}}}}, results)
		if len(merged) != 1 || len(merged[0].Vulns) != 1 || merged[0].Vulns[0].Source != awsServerlessAdvisory {
			t.Fatal("CVE alias duplicated or lost vendor evidence")
		}
	}
}
