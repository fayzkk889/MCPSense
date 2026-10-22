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
	"github.com/fayzkk889/MCPSense/internal/models"
	"github.com/fayzkk889/MCPSense/internal/utils"
)

// ScanMode describes how a scan is performed.
type ScanMode string

const (
	ModeStatic    ScanMode = "static"
	ModeLive      ScanMode = "live"
	ModeManifest  ScanMode = "manifest"
	ModeConfig    ScanMode = "config"
	ModeSkill     ScanMode = "skill"
	ModeAuto      ScanMode = "auto"
	ModeDirectory ScanMode = "directory"
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
	default:
		return nil, nil, fmt.Errorf("unknown scan mode: %s", mode)
	}

	if err != nil {
		return nil, nil, err
	}

	findings := s.runChecks(ctx)
	if len(ctx.Errors) > 0 {
		return nil, nil, ctx.Errors[0]
	}
	report := models.NewReport(target, string(mode), findings)
	report.Coverage = models.Coverage{State: "completed", Advisories: ctx.AdvisoryState, Surfaces: []string{}, SelectedChecks: []string{}, SkippedChecks: []string{}}
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
		} else {
			report.Coverage.SkippedChecks = append(report.Coverage.SkippedChecks, c.ID())
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
