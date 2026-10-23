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
			if v.Source != postgresAdvisory || v.ReviewedAt != vendorAdvisoryDate || strings.Contains(v.Summary, "unresolved") != tc.candidate {
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
		data, err := json.Marshal(map[string]interface{}{"fetched_at": time.Now().UTC(), "vulns": []interface{}{}})
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
	remote := []cve.Result{{Package: a, Vulns: []cve.Vuln{{ID: "GHSA-fph8-pg5w-78fv"}}}}
	merged := mergeAdvisoryResults(remote, reviewedVendorResults([]cve.Package{a, b}))
	if len(merged) != 2 || len(merged[0].Vulns) != 1 || merged[1].Package.Server != "second" {
		t.Fatalf("wrong merged results: %+v", merged)
	}
}
