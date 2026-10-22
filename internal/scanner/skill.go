package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/fayzkk889/MCPSense/internal/checks"
	"github.com/fayzkk889/MCPSense/internal/utils"
)

// skillFileMatchers decides whether a given path is a skill file we should scan.
func isSkillFile(path string) bool {
	base := filepath.Base(path)
	lowerBase := strings.ToLower(base)
	lowerPath := strings.ToLower(filepath.ToSlash(path))

	// Named instruction files
	switch lowerBase {
	case "skill.md", "claude.md", "agents.md", "agent.md", ".cursorrules", ".windsurfrules":
		return true
	}

	// Claude Code slash commands: .claude/commands/**/*.md
	if strings.Contains(lowerPath, "/.claude/commands/") && strings.HasSuffix(lowerBase, ".md") {
		return true
	}

	// Cursor rules: .cursor/rules/**/*.mdc
	if strings.Contains(lowerPath, "/.cursor/rules/") && strings.HasSuffix(lowerBase, ".mdc") {
		return true
	}

	return false
}

// scanSkill discovers and loads AI agent skill files into the scan context.
func (s *Scanner) scanSkill(target string, ctx *checks.ScanContext) error {
	ctx.SkillFiles = make(map[string]string)

	info, err := os.Stat(target)
	if err != nil {
		return err
	}

	// Single file target
	if !info.IsDir() {
		data, readErr := utils.ReadInput(target)
		if readErr != nil {
			return readErr
		}
		ctx.SkillFiles[target] = stripBOM(string(data))
		return nil
	}

	// Directory target: walk for skill files
	total := 0
	return filepath.WalkDir(target, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			// Skip common noise directories
			name := d.Name()
			if utils.SkipDirectory(name) && path != target {
				return filepath.SkipDir
			}
			return nil
		}
		if isSkillFile(path) {
			data, readErr := utils.ReadInput(path)
			if readErr != nil {
				return readErr
			}
			ctx.SkillFiles[path] = stripBOM(string(data))
			total += len(data)
			if total > utils.MaxScanBytes || len(ctx.SkillFiles) > 10000 {
				return fmt.Errorf("skill scan budget exceeded")
			}
		}
		return nil
	})
}

// stripBOM removes a leading UTF-8 BOM if present.
func stripBOM(s string) string {
	if len(s) >= 3 && s[0] == 0xEF && s[1] == 0xBB && s[2] == 0xBF {
		return s[3:]
	}
	return s
}
