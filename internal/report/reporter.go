package report

import (
	"io"

	"github.com/fayzkk889/MCPSense/internal/models"
)

// Reporter defines the interface for report output formats.
type Reporter interface {
	Write(report *models.Report, w io.Writer) error
}

// Format identifies the output format.
type Format string

const (
	FormatCLI   Format = "cli"
	FormatJSON  Format = "json"
	FormatSARIF Format = "sarif"
)

// New creates a Reporter for the given format.
func New(format Format, noColor bool) Reporter {
	switch format {
	case FormatJSON:
		return &JSONReporter{}
	case FormatSARIF:
		return &SARIFReporter{}
	default:
		return &CLIReporter{NoColor: noColor}
	}
}
