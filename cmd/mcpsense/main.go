package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/fayzkk889/MCPSense/internal/models"
	"github.com/fayzkk889/MCPSense/internal/report"
	"github.com/fayzkk889/MCPSense/internal/scanner"
)

var version = "0.1.0"

const configFile = ".mcpsenserc.json"

func main() {
	if err := rootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "mcpsense",
		Short: "Security scanner for MCP servers",
		Long:  "mcpsense scans MCP servers for security vulnerabilities, spec compliance issues, and tool quality problems.",
	}

	root.AddCommand(scanCmd())
	root.AddCommand(versionCmd())
	root.AddCommand(initConfigCmd())

	return root
}

func scanCmd() *cobra.Command {
	var (
		mode       string
		format     string
		minSev     string
		checkIDs   string
		excludeIDs string
		probe      bool
		outputFile string
		noColor    bool
	)

	cmd := &cobra.Command{
		Use:   "scan <target>",
		Short: "Scan an MCP server for security and quality issues",
		Long: `Scan an MCP server manifest, source directory, or live server.

Target auto-detection:
  *.json file       manifest mode
  directory         static analysis mode
  http:// or https: live mode (SSE endpoint)
  command string    live mode (stdio process)

Configuration is loaded from .mcpsenserc.json in the current directory.
CLI flags override config file values.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]

			// Load .mcpsenserc.json as a baseline; CLI flags override each field.
			cfg := loadConfig()

			// Resolve effective values: explicit CLI flag wins over config file default.
			if !cmd.Flags().Changed("format") && cfg.Format != "" {
				format = cfg.Format
			}
			if !cmd.Flags().Changed("severity") && cfg.MinSeverity != "" {
				minSev = cfg.MinSeverity
			}
			if !cmd.Flags().Changed("checks") && len(cfg.CheckIDs) > 0 {
				checkIDs = strings.Join(cfg.CheckIDs, ",")
			}
			if !cmd.Flags().Changed("exclude") && len(cfg.ExcludeIDs) > 0 {
				excludeIDs = strings.Join(cfg.ExcludeIDs, ",")
			}

			// Parse scan mode.
			scanMode := scanner.ModeAuto
			switch strings.ToLower(mode) {
			case "static":
				scanMode = scanner.ModeStatic
			case "live":
				scanMode = scanner.ModeLive
			case "manifest":
				scanMode = scanner.ModeManifest
			case "auto", "":
				// ModeAuto is the default, nothing to do.
			default:
				return fmt.Errorf("unknown mode %q, use: static, live, manifest, auto", mode)
			}

			// Parse check filter lists.
			var onlyIDs, skipIDs []string
			if checkIDs != "" {
				for _, id := range strings.Split(checkIDs, ",") {
					if id := strings.TrimSpace(id); id != "" {
						onlyIDs = append(onlyIDs, id)
					}
				}
			}
			if excludeIDs != "" {
				for _, id := range strings.Split(excludeIDs, ",") {
					if id := strings.TrimSpace(id); id != "" {
						skipIDs = append(skipIDs, id)
					}
				}
			}

			s := scanner.New(scanner.Options{
				Mode:        scanMode,
				EnableProbe: probe,
				CheckIDs:    onlyIDs,
				ExcludeIDs:  skipIDs,
			})

			rep, err := s.Scan(target)
			if err != nil {
				return fmt.Errorf("scan failed: %w", err)
			}

			// Apply minimum severity filter and recompute the score so it
			// reflects only the findings that are actually reported.
			minSeverity := parseSeverity(minSev)
			rep.Findings = filterBySeverity(rep.Findings, minSeverity)
			rep.Summary = summarize(rep.Findings)
			rep.CalculateScore()

			// Select output writer.
			out := os.Stdout
			if outputFile != "" {
				f, err := os.Create(outputFile)
				if err != nil {
					return fmt.Errorf("opening output file %q: %w", outputFile, err)
				}
				defer f.Close()
				out = f
			}

			// Render report.
			reporter := report.New(report.Format(strings.ToLower(format)), noColor)
			if err := reporter.Write(rep, out); err != nil {
				return fmt.Errorf("writing report: %w", err)
			}

			// Exit non-zero when critical or high findings remain after filtering.
			for _, f := range rep.Findings {
				if f.Severity == models.SeverityCritical || f.Severity == models.SeverityHigh {
					os.Exit(1)
				}
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&mode, "mode", "m", "auto", "Scan mode: static, live, manifest, auto")
	cmd.Flags().StringVarP(&format, "format", "f", "cli", "Output format: cli, json")
	cmd.Flags().StringVarP(&minSev, "severity", "s", "low", "Minimum severity to report: critical, high, medium, low, info")
	cmd.Flags().StringVarP(&checkIDs, "checks", "c", "", "Comma-separated list of check IDs to run (default: all)")
	cmd.Flags().StringVar(&excludeIDs, "exclude", "", "Comma-separated list of check IDs to skip")
	cmd.Flags().BoolVar(&probe, "probe", false, "Enable active probing in live mode")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file path (default: stdout)")
	cmd.Flags().BoolVar(&noColor, "no-color", false, "Disable colored output")

	return cmd
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("mcpsense v%s\n", version)
		},
	}
}

func initConfigCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Generate a .mcpsenserc.json config file with default settings",
		RunE: func(cmd *cobra.Command, args []string) error {
			if _, err := os.Stat(configFile); err == nil {
				return fmt.Errorf("%s already exists, remove it first if you want to regenerate", configFile)
			}
			cfg := defaultConfig()
			data, err := json.MarshalIndent(cfg, "", "  ")
			if err != nil {
				return err
			}
			if err := os.WriteFile(configFile, data, 0600); err != nil {
				return fmt.Errorf("writing config file: %w", err)
			}
			fmt.Printf("Created %s with default settings.\n", configFile)
			return nil
		},
	}
}

// MCPSenseConfig holds project-level configuration for CI/CD customization.
type MCPSenseConfig struct {
	MinSeverity string   `json:"min_severity"`
	ExcludeIDs  []string `json:"exclude_ids"`
	CheckIDs    []string `json:"check_ids"`
	Format      string   `json:"format"`
}

func defaultConfig() MCPSenseConfig {
	return MCPSenseConfig{
		MinSeverity: "low",
		ExcludeIDs:  []string{},
		CheckIDs:    []string{},
		Format:      "cli",
	}
}

// loadConfig reads .mcpsenserc.json from the current directory.
// Returns default config silently if the file does not exist.
func loadConfig() MCPSenseConfig {
	cfg := defaultConfig()
	data, err := os.ReadFile(configFile)
	if err != nil {
		return cfg // file absent is not an error
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not parse %s: %v\n", configFile, err)
	}
	return cfg
}

// parseSeverity converts a severity string to a models.Severity value.
func parseSeverity(s string) models.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return models.SeverityCritical
	case "high":
		return models.SeverityHigh
	case "medium":
		return models.SeverityMedium
	case "info":
		return models.SeverityInfo
	default:
		return models.SeverityLow
	}
}

// filterBySeverity returns only findings at or above the given minimum severity.
func filterBySeverity(findings []models.Finding, minSev models.Severity) []models.Finding {
	minScore := minSev.Score()
	var filtered []models.Finding
	for _, f := range findings {
		if f.Severity.Score() >= minScore {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// summarize recomputes the Summary from a (potentially filtered) findings slice.
func summarize(findings []models.Finding) models.Summary {
	bySeverity := make(map[models.Severity]int)
	byCategory := make(map[models.Category]int)
	for _, f := range findings {
		bySeverity[f.Severity]++
		byCategory[f.Category]++
	}
	return models.Summary{
		Total:      len(findings),
		BySeverity: bySeverity,
		ByCategory: byCategory,
	}
}
