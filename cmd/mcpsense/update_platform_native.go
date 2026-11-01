//go:build !js

package main

import (
	"crypto/sha256"
	"debug/buildinfo"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
)

func managementEnv(name string) string { return os.Getenv(name) }
func managementInteractive() bool {
	return isatty.IsTerminal(os.Stdout.Fd()) && isatty.IsTerminal(os.Stderr.Fd())
}
func managementCacheDir() (string, error) { return os.UserCacheDir() }

const ownModule = "github.com/fayzkk889/MCPSense"

var linkerVersion = regexp.MustCompile(`(?:^|\s)-X(?:\s+|=)main\.version=([0-9]+\.[0-9]+\.[0-9]+)(?:\s|$)`)

func nativeInstallationVersion(file string) (string, error) {
	st, err := os.Lstat(file)
	if err != nil {
		return "", err
	}
	if !st.Mode().IsRegular() {
		return "", fmt.Errorf("refusing a linked or non-regular command: %s", file)
	}
	info, err := buildinfo.ReadFile(file)
	if err != nil || info.Path != ownModule+"/cmd/mcpsense" || info.Main.Path != ownModule {
		return "", fmt.Errorf("command is not an identified MCPSense Go installation: %s", file)
	}
	v := strings.TrimPrefix(info.Main.Version, "v")
	if _, e := compareStable(v, v); e == nil {
		return v, nil
	}
	for _, setting := range info.Settings {
		if setting.Key == "-ldflags" {
			if m := linkerVersion.FindStringSubmatch(setting.Value); m != nil {
				if _, e := compareStable(m[1], m[1]); e == nil {
					return m[1], nil
				}
			}
		}
	}
	return "", fmt.Errorf("cannot identify the installed release version: %s", file)
}

func binaryHash(file string) ([32]byte, error) {
	var result [32]byte
	f, err := os.Open(file)
	if err != nil {
		return result, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, (64<<20)+1))
	if err != nil || n > 64<<20 {
		return result, fmt.Errorf("invalid updater binary")
	}
	copy(result[:], h.Sum(nil))
	return result, nil
}

// The caller identifies both files before entering this transaction. Keep an
// independent backup and roll back only while the replacement is still ours.
func swapNativeBinary(staged, target string, verify func() error) (string, error) {
	for _, p := range []string{staged, target} {
		st, err := os.Lstat(p)
		if err != nil {
			return "", err
		}
		if !st.Mode().IsRegular() {
			return "", fmt.Errorf("refusing linked/non-regular updater file")
		}
	}
	newHash, err := binaryHash(staged)
	if err != nil {
		return "", err
	}
	reservation, err := os.CreateTemp(filepath.Dir(target), filepath.Base(target)+".mcpsense-backup-")
	if err != nil {
		return "", err
	}
	backup := reservation.Name()
	if err = reservation.Close(); err != nil {
		return "", err
	}
	if err = os.Rename(target, backup); err != nil {
		_ = os.Remove(backup)
		return "", fmt.Errorf("cannot preserve old executable (it may be locked): %w", err)
	}
	if err = os.Rename(staged, target); err != nil {
		restore := os.Rename(backup, target)
		return backup, errors.Join(fmt.Errorf("replacement failed: %w", err), restore)
	}
	if err = verify(); err != nil {
		actual, readErr := binaryHash(target)
		if readErr != nil || actual != newHash {
			return backup, fmt.Errorf("verification failed; replacement changed, leaving it and backup %s for review: %w", backup, err)
		}
		removeErr := os.Remove(target)
		var restoreErr error
		if removeErr == nil {
			restoreErr = os.Rename(backup, target)
		}
		return backup, errors.Join(fmt.Errorf("update verification failed: %w", err), removeErr, restoreErr)
	}
	return backup, nil
}

func performPlatformUpdate(cmd *cobra.Command, plan updatePlan, repair bool) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	target, err := exec.LookPath("mcpsense")
	if err != nil {
		return fmt.Errorf("mcpsense is not on PATH; select the intended installation first")
	}
	target, err = filepath.Abs(target)
	if err != nil {
		return err
	}
	installed, err := nativeInstallationVersion(target)
	if err != nil {
		return err
	}
	if order, e := compareStable(installed, plan.Latest); e != nil || order > 0 {
		return fmt.Errorf("PATH selects a newer or unknown release; refusing to downgrade it")
	}
	if installed == plan.Latest {
		fmt.Fprintf(cmd.OutOrStdout(), "PATH already selects MCPSense %s: %s\n", installed, target)
		return nil
	}
	if !repair {
		a, _ := os.Stat(self)
		b, _ := os.Stat(target)
		if a == nil || b == nil || !os.SameFile(a, b) {
			return fmt.Errorf("another identified installation takes precedence: %s; rerun with --repair-path to update it", target)
		}
	}
	goTool, err := exec.LookPath("go")
	if err != nil {
		return fmt.Errorf("this native installation updates through Go; install with your Go toolchain or use the independent npm route")
	}
	stage, err := os.MkdirTemp(filepath.Dir(target), ".mcpsense-update-")
	if err != nil {
		return fmt.Errorf("installation directory is not writable: %w", err)
	}
	name := "mcpsense"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	staged := filepath.Join(stage, name)
	defer func() { _ = os.Remove(staged); _ = os.Remove(stage) }()
	fmt.Fprintf(cmd.ErrOrStderr(), "Updating %s → %s using Go...\n", installed, plan.Latest)
	build := exec.CommandContext(cmd.Context(), goTool, "install", ownModule+"/cmd/mcpsense@v"+plan.Latest)
	build.Dir = stage
	build.Env = append(os.Environ(), "GOBIN="+stage, "GOWORK=off", "GOFLAGS=", "CGO_ENABLED=0")
	build.Stdout = cmd.ErrOrStderr()
	build.Stderr = cmd.ErrOrStderr()
	if err = build.Run(); err != nil {
		return fmt.Errorf("Go update failed; previous executable preserved: %w", err)
	}
	v, err := nativeInstallationVersion(staged)
	if err != nil || v != plan.Latest {
		return fmt.Errorf("staged Go executable did not identify the requested release")
	}
	output, err := exec.CommandContext(cmd.Context(), staged, "version").Output()
	if err != nil || strings.TrimSpace(string(output)) != "mcpsense v"+plan.Latest {
		return fmt.Errorf("staged executable failed startup/version verification")
	}
	// Re-identify the target after the build; do not replace a concurrent edit.
	if current, e := nativeInstallationVersion(target); e != nil || current != installed {
		return fmt.Errorf("installation changed during the update; no replacement performed")
	}
	backup, err := swapNativeBinary(staged, target, func() error {
		resolved, e := exec.LookPath("mcpsense")
		if e != nil {
			return e
		}
		a, e := os.Stat(resolved)
		if e != nil {
			return e
		}
		b, e := os.Stat(target)
		if e != nil || !os.SameFile(a, b) {
			return fmt.Errorf("another command still takes precedence")
		}
		out, e := exec.CommandContext(cmd.Context(), resolved, "version").Output()
		if e != nil {
			return e
		}
		if strings.TrimSpace(string(out)) != "mcpsense v"+plan.Latest {
			return fmt.Errorf("plain command version did not change")
		}
		return nil
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Updated: mcpsense v%s\nCommand: %s\nPrevious executable backup: %s\n", plan.Latest, target, backup)
	return nil
}
