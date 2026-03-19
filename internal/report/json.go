package report

import (
	"encoding/json"
	"io"

	"github.com/faizan/mcpsense/internal/models"
)

// JSONReporter writes the full report as formatted JSON.
type JSONReporter struct{}

// Write serializes the report to JSON and writes it to w.
func (r *JSONReporter) Write(report *models.Report, w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}
