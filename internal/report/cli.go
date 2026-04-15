package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/fatih/color"
	"github.com/fayzkk889/MCPSense/internal/models"
)

// CLIReporter writes a human-readable colored terminal report.
type CLIReporter struct {
	NoColor bool
}

var (
	colorCritical = color.New(color.FgRed, color.Bold)
	colorHigh     = color.New(color.FgRed)
	colorMedium   = color.New(color.FgYellow)
	colorLow      = color.New(color.FgBlue)
	colorInfo     = color.New(color.FgHiBlack)
	colorBold     = color.New(color.Bold)
	colorGreen    = color.New(color.FgGreen)
	colorCyan     = color.New(color.FgCyan)
)

// Write renders the report to the given writer.
func (r *CLIReporter) Write(report *models.Report, w io.Writer) error {
	if r.NoColor {
		color.NoColor = true
	}

	r.writeHeader(w, report)
	r.writeFindings(w, report)
	r.writeSummary(w, report)

	return nil
}

func (r *CLIReporter) writeHeader(w io.Writer, report *models.Report) {
	line := strings.Repeat("=", 54)
	fmt.Fprint(w, "\n")
	fmt.Fprint(w, colorBold.Sprint("╔"+line+"╗\n"))
	fmt.Fprint(w, colorBold.Sprint("║  mcpsense v0.1.0 — MCP Server Security Scanner       ║\n"))
	fmt.Fprint(w, colorBold.Sprint("╠"+line+"╣\n"))
	fmt.Fprint(w, colorBold.Sprint("║  "))
	fmt.Fprintf(w, "Target:  %-43s", truncate(report.Target, 43))
	fmt.Fprint(w, colorBold.Sprint("║\n"))
	fmt.Fprint(w, colorBold.Sprint("║  "))
	fmt.Fprintf(w, "Mode:    %-43s", truncate(report.ScanMode, 43))
	fmt.Fprint(w, colorBold.Sprint("║\n"))
	fmt.Fprint(w, colorBold.Sprint("║  "))
	scoreStr := fmt.Sprintf("%d/100", report.Score)
	scoreColored := scoreColor(report.Score).Sprint(scoreStr)
	padding := 43 - len(scoreStr)
	fmt.Fprintf(w, "Score:   %s%s", scoreColored, strings.Repeat(" ", padding))
	fmt.Fprint(w, colorBold.Sprint("║\n"))
	fmt.Fprint(w, colorBold.Sprint("╚"+line+"╝\n"))
	fmt.Fprint(w, "\n")
}

func (r *CLIReporter) writeFindings(w io.Writer, report *models.Report) {
	if len(report.Findings) == 0 {
		colorGreen.Fprintln(w, "  No findings. Your server looks clean!")
		fmt.Fprintln(w)
		return
	}

	// Sort findings by severity weight (highest first).
	sorted := sortedFindings(report.Findings)

	for _, f := range sorted {
		r.writeFinding(w, f)
	}
}

func (r *CLIReporter) writeFinding(w io.Writer, f models.Finding) {
	sevColor := severityColor(f.Severity)
	sevLabel := strings.ToUpper(string(f.Severity))

	// Pad severity label to 10 chars.
	paddedSev := fmt.Sprintf("%-10s", sevLabel)

	fmt.Fprintf(w, "  %s %s  %s\n",
		sevColor.Sprint(paddedSev),
		colorBold.Sprint(f.ID),
		f.Title,
	)

	if f.Location.File != "" {
		loc := f.Location.File
		if f.Location.Line > 0 {
			loc = fmt.Sprintf("%s:%d", loc, f.Location.Line)
		}
		fmt.Fprintf(w, "           %s\n", colorCyan.Sprint("File: "+loc))
	}
	if f.Location.ToolName != "" {
		fmt.Fprintf(w, "           %s\n", colorCyan.Sprint("Tool: "+f.Location.ToolName))
	}

	fmt.Fprintf(w, "           %s %s\n", colorHiBlack("→"), f.Description)
	fmt.Fprintf(w, "           %s %s\n", colorBold.Sprint("Fix:"), f.Remediation)
	fmt.Fprintln(w)
}

func (r *CLIReporter) writeSummary(w io.Writer, report *models.Report) {
	divider := strings.Repeat("─", 56)
	fmt.Fprintf(w, "  %s\n", divider)

	parts := []string{}
	for _, sev := range models.AllSeverities() {
		count := report.Summary.BySeverity[sev]
		if count == 0 {
			count = 0
		}
		label := fmt.Sprintf("%d %s", count, capitalizeFirst(string(sev)))
		parts = append(parts, severityColor(sev).Sprint(label))
	}
	fmt.Fprintf(w, "  Summary: %s\n", strings.Join(parts, " │ "))
	fmt.Fprintf(w, "  %s\n\n", divider)
}

// sortedFindings returns findings sorted by severity weight descending.
func sortedFindings(findings []models.Finding) []models.Finding {
	sorted := make([]models.Finding, len(findings))
	copy(sorted, findings)

	// Simple insertion sort by severity score.
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && sorted[j].Severity.Score() > sorted[j-1].Severity.Score(); j-- {
			sorted[j], sorted[j-1] = sorted[j-1], sorted[j]
		}
	}
	return sorted
}

func severityColor(s models.Severity) *color.Color {
	switch s {
	case models.SeverityCritical:
		return colorCritical
	case models.SeverityHigh:
		return colorHigh
	case models.SeverityMedium:
		return colorMedium
	case models.SeverityLow:
		return colorLow
	default:
		return colorInfo
	}
}

func scoreColor(score int) *color.Color {
	switch {
	case score >= 80:
		return colorGreen
	case score >= 60:
		return colorMedium
	default:
		return colorCritical
	}
}

func colorHiBlack(s string) string {
	return colorInfo.Sprint(s)
}

// capitalizeFirst returns s with the first character uppercased.
func capitalizeFirst(s string) string {
	if s == "" {
		return ""
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
