package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
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
	ModeConfig   ScanMode = "config"
	ModeSkill    ScanMode = "skill"
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

// Scan runs the appropriate scan mode against the target and returns a report and the scan context.
func (s *Scanner) Scan(target string) (*models.Report, *checks.ScanContext, error) {
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
	report := models.NewReport(target, string(mode), findings)
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
		data, err := os.ReadFile(target)
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
