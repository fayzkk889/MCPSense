//go:build !js

package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestNativeSwapRollbackAndBackup(t *testing.T) {
	for _, fail := range []bool{false, true} {
		d := t.TempDir()
		target, stage := filepath.Join(d, "mcpsense"), filepath.Join(d, "staged")
		if e := os.WriteFile(target, []byte("old"), 0700); e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(stage, []byte("new"), 0700); e != nil {
			t.Fatal(e)
		}
		backup, e := swapNativeBinary(stage, target, func() error {
			if fail {
				return errors.New("startup failed")
			}
			return nil
		})
		data, _ := os.ReadFile(target)
		if fail {
			if e == nil || string(data) != "old" {
				t.Fatal(e, string(data))
			}
		} else {
			old, _ := os.ReadFile(backup)
			if e != nil || string(data) != "new" || string(old) != "old" {
				t.Fatal(e, string(data), string(old))
			}
		}
	}
}

func TestNativeIdentificationNeverExecutesUnknownFiles(t *testing.T) {
	file := filepath.Join(t.TempDir(), "mcpsense")
	if e := os.WriteFile(file, []byte("not an identified executable"), 0700); e != nil {
		t.Fatal(e)
	}
	if _, e := nativeInstallationVersion(file); e == nil {
		t.Fatal("unknown executable accepted")
	}
}
