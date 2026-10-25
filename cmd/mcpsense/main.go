package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime/debug"
	"strings"

	"github.com/spf13/cobra"

	"github.com/fayzkk889/MCPSense/internal/drift"
	"github.com/fayzkk889/MCPSense/internal/models"
	"github.com/fayzkk889/MCPSense/internal/nodebridge"
	"github.com/fayzkk889/MCPSense/internal/report"
	"github.com/fayzkk889/MCPSense/internal/scanner"
	"github.com/fayzkk889/MCPSense/internal/utils"
)

var version = "dev"
var errFindings = errors.New("findings at high or critical severity")

func init() {
	if version == "dev" {
		if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
			v := info.Main.Version
			if len(v) > 0 && v[0] == 'v' {
				v = v[1:]
			}
			version = v
		}
	}
}

const configFile = ".mcpsenserc.json"

func main() {
	if err := validateRuntime(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	ctx, cancel := commandContext()
	defer cancel()
	if err := rootCmd().ExecuteContext(ctx); err != nil {
		if errors.Is(err, errFindings) {
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, models.RedactText(err.Error()))
		os.Exit(2)
	}
}

func rootCmd() *cobra.Command {
	root := &cobra.Command{
		SilenceErrors: true,
		SilenceUsage:  true,
		Use:           "mcpsense",
		Short:         "Security scanner for MCP servers",
		Long:          "mcpsense scans MCP servers for security vulnerabilities, spec compliance issues, and tool quality problems.",
		Version:       version,
	}
	root.SetVersionTemplate("mcpsense v{{.Version}}\n")

	root.AddCommand(scanCmd())
	root.AddCommand(versionCmd())
	root.AddCommand(initConfigCmd())
	root.AddCommand(verifyCmd())

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
  package-lock.json npm dependency declarations (also npm-shrinkwrap.json)
  *.json file       manifest or MCP client configuration
  directory         combined source, config, manifest and skill inspection
  http:// or https: guarded live HTTP metadata discovery
  command string    live stdio; requires --allow-exec

Use --mode skill for individual instruction files.
Offline mode prohibits scanner networking and local server execution.
Private/loopback HTTP targets require --allow-private-network.

Configuration is loaded from .mcpsenserc.json in the current directory.
CLI flags override config file values.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]
			report.AppVersion = version

			// Load .mcpsenserc.json as a baseline; CLI flags override each field.
			cfg, configErr := loadConfig()
			if configErr != nil {
				return configErr
			}

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
			case "config":
				scanMode = scanner.ModeConfig
			case "skill":
				scanMode = scanner.ModeSkill
			case "dependencies":
				scanMode = scanner.ModeDependencies
			case "auto", "":
				// ModeAuto is the default, nothing to do.
			default:
				return fmt.Errorf("unknown mode %q, use: static, live, manifest, config, skill, dependencies, auto", mode)
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

			noCVE, _ := cmd.Flags().GetBool("no-cve")
			sarifOutput, _ := cmd.Flags().GetString("sarif-output")
			baselineArg, _ := cmd.Flags().GetString("baseline")
			dependencyFile, _ := cmd.Flags().GetString("dependencies")
			if format != "cli" && format != "json" && format != "sarif" {
				return fmt.Errorf("unknown output format")
			}
			if minSev != "critical" && minSev != "high" && minSev != "medium" && minSev != "low" && minSev != "info" {
				return fmt.Errorf("unknown severity")
			}
			paths := []string{target, dependencyFile, outputFile, sarifOutput, baselineArg}
			for i := 2; i < len(paths); i++ {
				if paths[i] == "" {
					continue
				}
				for j := 0; j < i; j++ {
					if paths[j] == "" {
						continue
					}
					a, _ := nodebridge.Abs(paths[i])
					b, _ := nodebridge.Abs(paths[j])
					same := a == b
					ai, ae := os.Stat(a)
					bi, be := os.Stat(b)
					if ae == nil && be == nil && os.SameFile(ai, bi) {
						same = true
					}
					if same {
						return fmt.Errorf("target, baseline and report paths must differ")
					}
				}
			}
			offline, _ := cmd.Flags().GetBool("offline")
			allowExec, _ := cmd.Flags().GetBool("allow-exec")
			serverArgs, _ := cmd.Flags().GetStringArray("server-arg")
			protocol, _ := cmd.Flags().GetString("protocol")
			allowPrivate, _ := cmd.Flags().GetBool("allow-private-network")
			if probe {
				return fmt.Errorf("active probes are not implemented; scanning enumerates metadata only")
			}
			if protocol != "auto" && protocol != "modern" && protocol != "legacy" {
				return fmt.Errorf("unknown protocol policy")
			}

			s := scanner.New(scanner.Options{
				Context:             cmd.Context(),
				Mode:                scanMode,
				EnableProbe:         probe,
				CheckIDs:            onlyIDs,
				ExcludeIDs:          skipIDs,
				DisableCVE:          noCVE || offline,
				Offline:             offline,
				AllowExec:           allowExec,
				ServerArgs:          serverArgs,
				Protocol:            protocol,
				AllowPrivateNetwork: allowPrivate,
				DependencyFile:      dependencyFile,
			})

			rep, ctx, err := s.Scan(target)
			if err != nil {
				return fmt.Errorf("scan failed: %w", err)
			}

			// --- Drift detection ---
			noBaseline, _ := cmd.Flags().GetBool("no-baseline")
			updateBaseline, _ := cmd.Flags().GetBool("update-baseline")
			baselineFlag, _ := cmd.Flags().GetString("baseline")

			// Drift applies to modes that have a tool/config surface (not static source scanning).
			driftApplies := ctx.Manifest != nil || ctx.ClientConfig != nil
			rep.Coverage.Baseline = "not_applicable"
			if noBaseline {
				rep.Coverage.Baseline = "skipped"
			}

			if driftApplies && !noBaseline {
				current := drift.BuildSnapshot(ctx.Manifest, ctx.ClientConfig, target, string(rep.ScanMode))

				baselinePath := baselineFlag
				if baselinePath == "" {
					p, err := drift.DefaultPath(target)
					if err == nil {
						baselinePath = p
					} else {
						return fmt.Errorf("baseline path unavailable; use --no-baseline or choose --baseline")
					}
				}

				if baselinePath != "" {
					if updateBaseline {
						rep.Coverage.Baseline = "updated"
						if err := drift.Save(baselinePath, current); err != nil {
							return fmt.Errorf("could not update baseline: %w", err)
						} else {
							fmt.Fprintln(os.Stderr, "Baseline updated.")
						}
					} else if drift.Exists(baselinePath) {
						rep.Coverage.Baseline = "compared"
						prev, err := drift.Load(baselinePath)
						if err != nil {
							return fmt.Errorf("could not load baseline: %w", err)
						} else {
							if prev.Target != current.Target || prev.Mode != current.Mode {
								return fmt.Errorf("baseline target or mode differs; review and explicitly update baseline")
							}
							baselineData, err := drift.MarshalSnapshot(prev)
							if err != nil {
								return err
							}
							rep.Coverage.BaselineHash = models.HashIdentity(string(baselineData))
							rep.Coverage.BaselineFields, rep.Coverage.BaselineWarning = drift.ComparisonCoverage(prev, current)
							driftFindings := drift.Diff(prev, current)
							for i := range driftFindings {
								if ctx.ManifestFile != "" {
									driftFindings[i].Location.File = ctx.ManifestFile
								} else {
									for name, path := range ctx.ComponentFiles {
										if models.HashIdentity(name) == driftFindings[i].Location.ToolName {
											driftFindings[i].Location.File = path
										}
									}
								}
							}
							rep.Findings = append(rep.Findings, driftFindings...)
						}
					} else {
						rep.Coverage.Baseline = "created"
						// First scan: save baseline so future scans can detect drift.
						if err := drift.Save(baselinePath, current); err != nil {
							return fmt.Errorf("could not save baseline: %w", err)
						} else {
							fmt.Fprintf(os.Stderr, "Baseline saved. Future scans of this target will detect drift.\n")
						}
					}
				}
			}

			// Apply minimum severity filter and recompute the score so it
			// reflects only the findings that are actually reported.
			minSeverity := parseSeverity(minSev)
			rep.Findings = filterBySeverity(rep.Findings, minSeverity)
			rep.Summary = summarize(rep.Findings)
			rep.CalculateScore()
			rep.MinSeverity = minSev
			rep.FinalizeEvidence()

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
			showDiff, _ := cmd.Flags().GetBool("show-diff")
			reporter := report.New(report.Format(strings.ToLower(format)), noColor)
			if cli, ok := reporter.(*report.CLIReporter); ok {
				cli.ShowDiff = showDiff
			}

			if err := reporter.Write(rep, out); err != nil {
				return fmt.Errorf("writing report: %w", err)
			}
			if sarifOutput != "" {
				if sarifOutput == outputFile || sarifOutput == target {
					return fmt.Errorf("SARIF output must differ from target and primary output")
				}
				f, err := os.OpenFile(sarifOutput, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
				if err != nil {
					return fmt.Errorf("opening SARIF output: %w", err)
				}
				err = (&report.SARIFReporter{}).Write(rep, f)
				closeErr := f.Close()
				if err != nil {
					return err
				}
				if closeErr != nil {
					return closeErr
				}
			}

			// Exit non-zero when critical or high findings remain after filtering.
			for _, f := range rep.Findings {
				if f.Severity == models.SeverityCritical || f.Severity == models.SeverityHigh {
					return errFindings
				}
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&mode, "mode", "m", "auto", "Scan mode: static, live, manifest, config, skill, dependencies, auto")
	cmd.Flags().String("dependencies", "", "Explicit npm v2/v3 lockfile to include; online advisories send recognized package names/versions to OSV")
	cmd.Flags().StringVarP(&format, "format", "f", "cli", "Output format: cli, json, sarif")
	cmd.Flags().StringVarP(&minSev, "severity", "s", "low", "Minimum severity to report: critical, high, medium, low, info")
	cmd.Flags().StringVarP(&checkIDs, "checks", "c", "", "Comma-separated list of check IDs to run (default: all)")
	cmd.Flags().StringVar(&excludeIDs, "exclude", "", "Comma-separated list of check IDs to skip")
	cmd.Flags().BoolVar(&probe, "probe", false, "Reserved; active probing is not implemented")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file path (default: stdout)")
	cmd.Flags().BoolVar(&noColor, "no-color", false, "Disable colored output")

	cmd.Flags().String("baseline", "", "Path to a baseline snapshot file for drift detection (default: ~/.mcpsense/snapshots/)")
	cmd.Flags().Bool("update-baseline", false, "Accept the current server state as the new drift baseline")
	cmd.Flags().Bool("no-baseline", false, "Skip drift detection for this scan")
	cmd.Flags().Bool("show-diff", false, "Compatibility flag; protected baselines do not retain raw before/after text")

	cmd.Flags().Bool("no-cve", false, "Skip CVE cross-referencing against OSV.dev")
	cmd.Flags().Bool("offline", false, "Disable all network calls (implies --no-cve)")
	cmd.Flags().Bool("allow-exec", false, "Allow execution of the explicitly selected local MCP server (unavailable offline)")
	cmd.Flags().StringArray("server-arg", nil, "Argument passed literally to the local server; repeat for each argument")
	cmd.Flags().String("sarif-output", "", "Write SARIF from the same scan in addition to the selected output")
	cmd.Flags().String("protocol", "auto", "Live metadata protocol: auto, modern (2026-07-28), legacy (initialize)")
	cmd.Flags().Bool("allow-private-network", false, "Allow explicitly targeted loopback/private MCP addresses; link-local and metadata addresses remain blocked")

	return cmd
}

func versionCmd() *cobra.Command {
	return newVersionCmd()
}

func initConfigCmd() *cobra.Command {
	example := false
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Generate a .mcpsenserc.json config file with default settings",
		RunE: func(cmd *cobra.Command, args []string) error {
			if example {
				return writeExample(cmd)
			}
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
			fmt.Fprintln(cmd.OutOrStdout(), "This configures MCPSense; it does not create an MCP server config.")
			fmt.Fprintln(cmd.OutOrStdout(), "For a safe first scan, run: mcpsense init --example")
			return nil
		},
	}
	cmd.Flags().BoolVar(&example, "example", false, "Create a safe example mcp.json for a first offline scan (never overwrite)")
	return cmd
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
func loadConfig() (MCPSenseConfig, error) {
	cfg := defaultConfig()
	data, err := utils.ReadInput(configFile)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, fmt.Errorf("project configuration unreadable")
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("invalid project configuration JSON")
	}
	return cfg, nil
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
	filtered := make([]models.Finding, 0)
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
	byOWASP := make(map[string]int)
	for _, f := range findings {
		bySeverity[f.Severity]++
		byCategory[f.Category]++
		if f.OWASP != "" {
			byOWASP[f.OWASP]++
		}
	}
	return models.Summary{
		Total:      len(findings),
		BySeverity: bySeverity,
		ByCategory: byCategory,
		ByOWASP:    byOWASP,
	}
}
