package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/fayzkk889/MCPSense/internal/checks"
	"github.com/fayzkk889/MCPSense/internal/detection"
	"github.com/fayzkk889/MCPSense/internal/inventory"
	"github.com/fayzkk889/MCPSense/internal/models"
	"github.com/fayzkk889/MCPSense/internal/utils"
)

// ScanMode describes how a scan is performed.
type ScanMode string

const (
	ModeStatic       ScanMode = "static"
	ModeLive         ScanMode = "live"
	ModeManifest     ScanMode = "manifest"
	ModeConfig       ScanMode = "config"
	ModeSkill        ScanMode = "skill"
	ModeAuto         ScanMode = "auto"
	ModeDirectory    ScanMode = "directory"
	ModeDependencies ScanMode = "dependencies"
)

// Options configures the scanner behavior.
type Options struct {
	Context             context.Context
	Timeout             time.Duration
	Mode                ScanMode
	EnableProbe         bool
	CheckIDs            []string // if non-empty, run only these checks
	ExcludeIDs          []string // checks to skip
	DisableCVE          bool     // set by --no-cve or --offline
	Offline             bool     // disallow live networking and subprocesses as well as advisories
	AllowExec           bool     // explicit permission to start a local server
	ServerArgs          []string // explicit argv; target is the executable path
	Protocol            string   // auto, modern or legacy
	AllowPrivateNetwork bool
	DependencyFile      string // explicit opt-in; never discovered recursively
}

// Scanner orchestrates the scan process.
type Scanner struct {
	registry *checks.Registry
	patterns *detection.PatternEngine
	opts     Options
}

// New creates a Scanner with the given options.
func New(opts Options) *Scanner {
	if opts.Context == nil {
		opts.Context = context.Background()
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 20 * time.Second
	}
	s := &Scanner{
		registry: checks.NewRegistry(),
		patterns: detection.NewPatternEngine(),
		opts:     opts,
	}
	if opts.DisableCVE || opts.Offline {
		for _, c := range s.registry.AllChecks() {
			if cveCheck, ok := c.(*checks.DependencyCVECheck); ok {
				cveCheck.Disabled = true
			}
		}
	}
	return s
}

// Scan runs the appropriate scan mode against the target and returns a report and the scan context.
func (s *Scanner) Scan(target string) (*models.Report, *checks.ScanContext, error) {
	if err := s.opts.Context.Err(); err != nil {
		return nil, nil, err
	}
	known := make(map[string]bool)
	for _, check := range s.registry.AllChecks() {
		known[check.ID()] = true
	}
	for _, ids := range [][]string{s.opts.CheckIDs, s.opts.ExcludeIDs} {
		for _, id := range ids {
			if !known[id] {
				return nil, nil, fmt.Errorf("unknown check ID %q", id)
			}
		}
	}
	if len(s.opts.CheckIDs) > 0 && len(s.opts.ExcludeIDs) > 0 {
		return nil, nil, fmt.Errorf("checks and exclude cannot be combined")
	}
	mode := s.opts.Mode
	if mode == ModeAuto || mode == "" {
		mode = detectMode(target)
		if info, err := os.Stat(target); err == nil && info.IsDir() {
			mode = ModeDirectory
		}
	}
	if mode == ModeLive && s.opts.Offline {
		return nil, nil, fmt.Errorf("offline policy prohibits live network access and server execution")
	}
	if mode == ModeLive && !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") && !s.opts.AllowExec {
		return nil, nil, fmt.Errorf("local server execution requires --allow-exec")
	}

	ctx := &checks.ScanContext{
		Context:  s.opts.Context,
		Patterns: s.patterns,
	}

	var err error
	switch mode {
	case ModeDirectory:
		err = s.scanStatic(target, ctx)
		if err == nil {
			err = s.scanSkill(target, ctx)
		}
	case ModeManifest:
		err = s.scanManifest(target, ctx)
	case ModeConfig:
		err = s.scanConfig(target, ctx)
	case ModeStatic:
		err = s.scanStatic(target, ctx)
	case ModeLive:
		err = s.scanLive(target, ctx)
	case ModeSkill:
		err = s.scanSkill(target, ctx)
	case ModeDependencies:
		if s.opts.DependencyFile != "" {
			return nil, nil, fmt.Errorf("dependencies mode already selects an inventory; omit --dependencies")
		}
		ctx.Dependencies, err = inventory.ReadNPM(target)
	default:
		return nil, nil, fmt.Errorf("unknown scan mode: %s", mode)
	}

	if err != nil {
		return nil, nil, err
	}
	if s.opts.DependencyFile != "" {
		ctx.Dependencies, err = inventory.ReadNPM(s.opts.DependencyFile)
		if err != nil {
			return nil, nil, err
		}
	}
	if ctx.Dependencies != nil {
		ctx.InputPaths = append(ctx.InputPaths, ctx.Dependencies.Input)
	}

	findings := s.runChecks(ctx)
	for i := range findings {
		f := &findings[i]
		if f.ID != "CVE-001" && ctx.ManifestFile != "" && (f.Location.File == "" || f.Location.ToolName != "" || f.ID == "SPEC-004" || f.ID == "SEC-006") {
			f.Location.File = ctx.ManifestFile
		}
		if f.ID == "SEC-014" || f.ID == "SEC-015" || f.ID == "SEC-016" || (f.ID == "CVE-001" && f.Location.ToolName == "") {
			if path, ok := ctx.ComponentFiles[f.Location.File]; ok {
				f.Location.File = path
			}
		}
	}
	if len(ctx.Errors) > 0 {
		return nil, nil, ctx.Errors[0]
	}
	report := models.NewReport(target, string(mode), findings)
	report.Dependencies = ctx.Dependencies
	report.Coverage = models.Coverage{DetectorProfile: checks.DetectorProfile(), State: "completed", Advisories: ctx.AdvisoryState, AdvisoryScope: ctx.AdvisoryScope, Surfaces: []string{}, SelectedChecks: []string{}, SkippedChecks: []string{}}
	if report.Coverage.Advisories == "" {
		report.Coverage.Advisories = "skipped"
	}
	if len(ctx.SourceFiles) > 0 {
		report.Coverage.Surfaces = append(report.Coverage.Surfaces, "source")
	}
	if len(ctx.SkillFiles) > 0 {
		report.Coverage.Surfaces = append(report.Coverage.Surfaces, "skills")
	}
	if ctx.ClientConfig != nil {
		report.Coverage.Surfaces = append(report.Coverage.Surfaces, "config")
	}
	if ctx.Manifest != nil {
		report.Coverage.Surfaces = append(report.Coverage.Surfaces, "manifest")
		report.Coverage.Protocol = ctx.Manifest.ProtocolVersion
	}
	if ctx.Dependencies != nil {
		report.Coverage.Surfaces = append(report.Coverage.Surfaces, "dependencies")
		report.Coverage.DependencyScope = []string{ctx.Dependencies.Format}
		for _, dep := range ctx.Dependencies.Packages {
			// Version/content may change during remediation, but silently removing
			// packages or changing their identity is not equivalent coverage.
			report.Coverage.DependencyScope = append(report.Coverage.DependencyScope, models.HashIdentity(dep.Path+"\x00"+dep.Name+"\x00"+dep.Unresolved))
		}
	}
	for path := range ctx.SourceFiles {
		report.Coverage.Inputs = append(report.Coverage.Inputs, models.HashIdentity(filepath.ToSlash(filepath.Clean(path))))
	}
	for path := range ctx.SkillFiles {
		report.Coverage.Inputs = append(report.Coverage.Inputs, models.HashIdentity(filepath.ToSlash(filepath.Clean(path))))
	}
	for _, path := range ctx.InputPaths {
		report.Coverage.Inputs = append(report.Coverage.Inputs, models.HashIdentity(filepath.ToSlash(filepath.Clean(path))))
	}
	if mode != ModeDirectory && mode != ModeStatic && mode != ModeSkill {
		report.Coverage.Inputs = append(report.Coverage.Inputs, models.HashIdentity(target))
	}
	sort.Strings(report.Coverage.Inputs)
	if len(report.Coverage.Surfaces) == 0 {
		return nil, nil, fmt.Errorf("no supported readable input in requested scope")
	}
	for _, c := range s.registry.AllChecks() {
		selected := len(s.opts.CheckIDs) == 0
		for _, id := range s.opts.CheckIDs {
			if id == c.ID() {
				selected = true
			}
		}
		for _, id := range s.opts.ExcludeIDs {
			if id == c.ID() {
				selected = false
			}
		}
		if selected {
			report.Coverage.SelectedChecks = append(report.Coverage.SelectedChecks, c.ID())
			if c.ID() == "SEC-001" && ctx.Manifest != nil {
				report.Coverage.MetadataFields = []string{"server.description", "server.instructions", "tools.names_titles_descriptions", "tools.inputSchema_strings_keys", "tools.outputSchema_strings_keys", "tools.annotation_titles", "resources.names_uris_descriptions", "prompts.names_descriptions_arguments"}
			}
		} else {
			report.Coverage.SkippedChecks = append(report.Coverage.SkippedChecks, c.ID())
		}
	}
	report.Coverage.Unassessed = []string{"runtime_behavior_and_tool_results", "resource_contents_and_prompt_bodies", "unrecognized_metadata_extensions", "general_semantic_understanding", "project_and_transitive_dependency_inventory", "authorization_enforcement_and_session_isolation", "runtime_resource_limits"}
	if ctx.Dependencies != nil {
		report.Coverage.Unassessed[4] = "dependencies_outside_selected_npm_lock_and_actual_installed_code"
		for _, dep := range ctx.Dependencies.Packages {
			if dep.Unresolved != "" {
				report.Coverage.Unassessed = append(report.Coverage.Unassessed, "unresolved_npm_lock_entries")
				break
			}
		}
	}
	var protected []string
	if ctx.ClientConfig != nil {
		for _, entry := range ctx.ClientConfig.MCPServers {
			for _, value := range entry.Env {
				protected = append(protected, value)
			}
			protected = append(protected, entry.Args...)
		}
	}
	report = report.ProtectedCopy(protected)
	return report, ctx, nil
}

func (s *Scanner) runChecks(ctx *checks.ScanContext) []models.Finding {
	switch {
	case len(s.opts.CheckIDs) > 0:
		return s.registry.RunByIDs(ctx, s.opts.CheckIDs)
	case len(s.opts.ExcludeIDs) > 0:
		return s.registry.RunExcluding(ctx, s.opts.ExcludeIDs)
	default:
		return s.registry.RunAll(ctx)
	}
}

// hasSkillMarkers reports whether a directory contains AI agent skill files.
func hasSkillMarkers(dir string) bool {
	markers := []string{
		filepath.Join(dir, ".claude", "commands"),
		filepath.Join(dir, "SKILL.md"),
		filepath.Join(dir, ".cursor", "rules"),
		filepath.Join(dir, ".cursorrules"),
		filepath.Join(dir, ".windsurfrules"),
		filepath.Join(dir, "CLAUDE.md"),
		filepath.Join(dir, "AGENTS.md"),
	}
	for _, m := range markers {
		if _, err := os.Stat(m); err == nil {
			return true
		}
	}
	return false
}

// detectMode infers the scan mode from the target string.
func detectMode(target string) ScanMode {
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return ModeLive
	}

	if strings.HasSuffix(target, ".json") {
		if base := filepath.Base(target); base == "package-lock.json" || base == "npm-shrinkwrap.json" {
			return ModeDependencies
		}
		// Try to detect whether this is a client config or a manifest.
		// Client configs have a top-level "mcpServers" key.
		data, err := utils.ReadInput(target)
		if err == nil {
			// Strip UTF-8 BOM if present
			if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
				data = data[3:]
			}
			var raw map[string]json.RawMessage
			if json.Unmarshal(data, &raw) == nil {
				if _, hasServers := raw["mcpServers"]; hasServers {
					return ModeConfig
				}
				if _, hasServers := raw["servers"]; hasServers {
					return ModeConfig
				}
			}
		}
		return ModeManifest
	}

	// If the target is a regular file (not a directory) AND it is executable, return ModeLive
	info, err := os.Stat(target)
	if err == nil {
		if info.IsDir() {
			if hasSkillMarkers(target) {
				return ModeSkill
			}
			return ModeStatic
		}
		// Check for executable: on Unix check permission bits, on Windows check extension
		isExec := false
		if runtime.GOOS == "windows" {
			ext := strings.ToLower(filepath.Ext(target))
			isExec = ext == ".exe" || ext == ".bat" || ext == ".cmd"
		} else {
			isExec = info.Mode().Perm()&0111 != 0
		}
		if isExec {
			return ModeLive
		}
		return ModeStatic
	}

	// A target that looks like a shell command (contains spaces, starts with ./).
	if strings.Contains(target, " ") || strings.HasPrefix(target, "./") || strings.HasPrefix(target, "../") {
		return ModeLive
	}

	// Default to static analysis for directory targets.
	return ModeStatic
}
