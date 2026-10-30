package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/fayzkk889/MCPSense/internal/models"
)

func TestAdvisoryConflictSurvivesJSONSARIFAndPrivacy(t *testing.T) {
	evidence := &models.AdvisoryEvidence{ID: "TEST-1", Applicability: "conflicting_sources", FeedURL: "https://feed.example.invalid/item?token=PRIVATE", ReviewedURL: "https://publisher.example.invalid/review", ReviewedAt: "2026-10-30", ReviewNote: "password=PRIVATE"}
	r := models.NewReport("fixture", "dependencies", []models.Finding{{ID: "CVE-001", Title: "Advisory applicability conflict", Severity: models.SeverityHigh, Category: models.CategorySecurity, Confidence: "unresolved_applicability", Advisory: evidence}})
	for _, format := range []Format{FormatJSON, FormatSARIF} {
		var out bytes.Buffer
		if err := New(format, true).Write(r, &out); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out.String(), "PRIVATE") {
			t.Fatal("advisory fields leaked credentials")
		}
		var value map[string]interface{}
		if err := json.Unmarshal(out.Bytes(), &value); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), "conflicting_sources") || !strings.Contains(out.String(), "publisher.example.invalid") || !strings.Contains(out.String(), "unresolved_applicability") {
			t.Fatal("lost advisory review evidence", out.String())
		}
	}
	if !strings.Contains(evidence.FeedURL, "PRIVATE") || evidence.ReviewNote != "password=PRIVATE" {
		t.Fatal("report export mutated original evidence")
	}
	if r.ProtectedCopy(nil).Assessment.State != "review_required" {
		t.Fatal("conflict incorrectly established safety")
	}
}
