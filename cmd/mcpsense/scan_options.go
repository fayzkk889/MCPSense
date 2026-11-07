package main

import (
	"github.com/fayzkk889/MCPSense/internal/models"
	"github.com/fayzkk889/MCPSense/internal/report"
	"github.com/fayzkk889/MCPSense/internal/scanner"
)

// Both the CLI validator/help and the MCP schema/status use these choices. A
// new CLI mode or report format cannot leave a second MCP list behind.
func scanModeNames() []string {
	return []string{string(scanner.ModeStatic), string(scanner.ModeLive), string(scanner.ModeManifest), string(scanner.ModeConfig), string(scanner.ModeSkill), string(scanner.ModeDependencies), string(scanner.ModeAuto)}
}

func reportFormatNames() []string {
	return []string{string(report.FormatCLI), string(report.FormatJSON), string(report.FormatSARIF)}
}

func severityNames() []string {
	names := []string{}
	for _, severity := range models.AllSeverities() {
		names = append(names, severity.String())
	}
	return names
}

func containsChoice(value string, choices []string) bool {
	for _, choice := range choices {
		if value == choice {
			return true
		}
	}
	return false
}
