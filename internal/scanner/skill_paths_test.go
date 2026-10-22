package scanner

import (
	"path/filepath"
	"testing"
)

func TestRelativeRootSkillPaths(t *testing.T) {
	for _, path := range []string{".claude/commands/review.md", ".claude/commands/nested/review.md", ".cursor/rules/security.mdc", filepath.FromSlash("C:/project/.claude/commands/review.md")} {
		if !isSkillFile(path) {
			t.Errorf("skill path omitted: %s", path)
		}
	}
	for _, path := range []string{"commands/review.md", ".cursor/rules/unrelated.txt"} {
		if isSkillFile(path) {
			t.Errorf("non-skill path included: %s", path)
		}
	}
}
