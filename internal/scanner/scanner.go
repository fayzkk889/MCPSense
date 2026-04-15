package scanner

import (
	"fmt"
	"strings"

	"github.com/fayzkk889/MCPSense/internal/checks"
	"github.com/fayzkk889/MCPSense/internal/detection"
	"github.com/fayzkk889/MCPSense/internal/models"
)

// ScanMode describes how a scan is performed.
type ScanMode string

const (
	ModeStatic   ScanMode = "static"
	ModeLive     ScanMode = "live"
	ModeManifest ScanMode = "manifest"
	ModeAuto     ScanMode = "auto"
)

// Options configures the scanner behavior.
type Options struct {
	Mode        ScanMode
	EnableProbe bool
	CheckIDs    []string // if non-empty, run only these checks
	ExcludeIDs  []string // checks to skip
}

// Scanner orchestrates the scan process.
type Scanner struct {
	registry *checks.Registry
	patterns *detection.PatternEngine
	opts     Options
}

// New creates a Scanner with the given options.
func New(opts Options) *Scanner {
	return &Scanner{
		registry: checks.NewRegistry(),
		patterns: detection.NewPatternEngine(),
		opts:     opts,
	}
}

// Scan runs the appropriate scan mode against the target and returns a report.
func (s *Scanner) Scan(target string) (*models.Report, error) {
	mode := s.opts.Mode
	if mode == ModeAuto || mode == "" {
		mode = detectMode(target)
	}

	ctx := &checks.ScanContext{
		Patterns: s.patterns,
	}

	var err error
	switch mode {
	case ModeManifest:
		err = s.scanManifest(target, ctx)
	case ModeStatic:
		err = s.scanStatic(target, ctx)
	case ModeLive:
		err = s.scanLive(target, ctx)
	default:
		return nil, fmt.Errorf("unknown scan mode: %s", mode)
	}

	if err != nil {
		return nil, err
	}

	findings := s.runChecks(ctx)
	report := models.NewReport(target, string(mode), findings)
	return report, nil
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

// detectMode infers the scan mode from the target string.
func detectMode(target string) ScanMode {
	if strings.HasSuffix(target, ".json") {
		return ModeManifest
	}
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		return ModeLive
	}
	// A target that looks like a shell command (contains spaces, starts with ./).
	if strings.Contains(target, " ") || strings.HasPrefix(target, "./") || strings.HasPrefix(target, "../") {
		return ModeLive
	}
	// Default to static analysis for directory targets.
	return ModeStatic
}
