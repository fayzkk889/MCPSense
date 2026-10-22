package utils

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSourceSymlinkNotRead(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "private.go")
	if err := os.WriteFile(outside, []byte("SYNTHETIC_PRIVATE_TEXT"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "linked.go")); err != nil {
		t.Skip("symlink permission unavailable")
	}
	if _, err := DiscoverSourceFiles(root); err == nil {
		t.Fatal("symlinked source silently read")
	}
}
