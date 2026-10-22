package utils

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInputSizeLimit(t *testing.T) {
	p := filepath.Join(t.TempDir(), "oversized.json")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate(MaxInputBytes + 1); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadInput(p); err == nil {
		t.Fatal("oversized file accepted")
	}
}
