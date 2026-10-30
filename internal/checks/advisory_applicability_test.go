package checks

import (
	"strings"
	"testing"

	"github.com/fayzkk889/MCPSense/internal/cve"
	"github.com/fayzkk889/MCPSense/internal/models"
)

func TestAdvisoryConflictRetainsEvidenceAndWarning(t *testing.T) {
	pkg := cve.Package{Name: "tensorlake", Ecosystem: "npm", Version: "0.5.143", Server: "selected-lock"}
	for _, id := range []string{"MAL-2026-17650", "GHSA-rqxj-g25x-4v9v"} {
		f := advisoryFinding(pkg, cve.Vuln{ID: id, Summary: "Malicious code reported by feed"}, models.Location{File: "selected-lock"})
		if f.Advisory == nil || f.Advisory.Applicability != "conflicting_sources" || f.Confidence != "unresolved_applicability" || f.Severity != models.SeverityHigh {
			t.Fatalf("conflict hidden or asserted affected: %+v", f)
		}
		if f.Advisory.ID != id || !strings.Contains(f.Advisory.FeedURL, id) || f.Advisory.ReviewedURL != tensorlakeAdvisory || f.Advisory.ReviewedAt != "2026-10-30" || !strings.Contains(f.Description, "unaffected") || !strings.Contains(f.Title, "conflict") {
			t.Fatalf("missing conflict provenance: %+v", f)
		}
	}
}

func TestAdvisoryReviewIsNarrowAndDoesNotSuppressMatches(t *testing.T) {
	for _, tc := range []struct{ name, ecosystem, version, id, state string }{
		{"tensorlake", "npm", "0.5.144", "MAL-2026-17650", "reported_affected"},
		{"tensorlake", "npm", "0.5.145", "MAL-2026-17650", "reported_affected"},
		{"tensorlake", "npm", "0.5.143+local", "MAL-2026-17650", "reported_affected"},
		{"tensorlake", "npm", "", "MAL-2026-17650", "version_unresolved"},
		{"other", "npm", "0.5.143", "MAL-2026-17650", "reported_affected"},
		{"tensorlake", "PyPI", "0.5.143", "MAL-2026-17650", "reported_affected"},
		{"tensorlake", "npm", "0.5.143", "OTHER-ADVISORY", "reported_affected"},
	} {
		f := advisoryFinding(cve.Package{Name: tc.name, Ecosystem: tc.ecosystem, Version: tc.version}, cve.Vuln{ID: tc.id}, models.Location{})
		if f.ID != "CVE-001" || f.Advisory == nil || f.Advisory.Applicability != tc.state || f.Advisory.ReviewedURL != "" || !strings.Contains(f.Title, tc.id) {
			t.Fatalf("review leaked outside exact identity: %+v %+v", tc, f)
		}
	}
}
