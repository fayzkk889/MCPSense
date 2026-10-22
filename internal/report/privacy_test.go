package report

import (
	"bytes"
	"github.com/fayzkk889/MCPSense/internal/models"
	"strings"
	"testing"
)

func TestAllReportFormatsProtectSecrets(t *testing.T) {
	for _, format := range []Format{FormatCLI, FormatJSON, FormatSARIF} {
		r := models.NewReport("https://user:SYNTHETIC_URL_PASSWORD@example.invalid/?token=SYNTHETIC_QUERY", "config", []models.Finding{{ID: "DRIFT-002", Title: "changed", Description: "token=SYNTHETIC_TOKEN", Severity: models.SeverityHigh, DiffOld: "SYNTHETIC_OLD", DiffNew: "SYNTHETIC_NEW"}})
		var b bytes.Buffer
		if err := New(format, true).Write(r, &b); err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{"SYNTHETIC_URL_PASSWORD", "SYNTHETIC_QUERY", "SYNTHETIC_TOKEN", "SYNTHETIC_OLD", "SYNTHETIC_NEW"} {
			if strings.Contains(b.String(), secret) {
				t.Errorf("%s leaks %s", format, secret)
			}
		}
		if r.Findings[0].DiffOld == "" {
			t.Fatal("reporter mutated source")
		}
	}
}
