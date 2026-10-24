package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/fayzkk889/MCPSense/internal/models"
)

func TestExplicitDependencyInventoryOfflineAndScope(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "package-lock.json")
	lock := `{"lockfileVersion":3,"packages":{"":{},"node_modules/lodash":{"version":"4.17.20","resolved":"https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"}}}`
	if err := os.WriteFile(file, []byte(lock), 0600); err != nil {
		t.Fatal(err)
	}
	r, _, err := New(Options{Offline: true}).Scan(file)
	if err != nil {
		t.Fatal(err)
	}
	if r.ScanMode != "dependencies" || r.Coverage.Advisories != "skipped" || r.Dependencies == nil || len(r.Dependencies.Packages) != 1 {
		t.Fatalf("incorrect scope: %+v", r)
	}
	r2, _, err := New(Options{Offline: true, Mode: ModeDependencies}).Scan(file)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := models.VerifyReports(r, r2); err != nil {
		t.Fatal(err)
	}
	// Updating a version retains comparable scope. Removing a package does not.
	r2.Coverage.DependencyScope = r2.Coverage.DependencyScope[:1]
	if _, err := models.VerifyReports(r, r2); err == nil {
		t.Fatal("removal counted as remediation")
	}
	if _, _, err := New(Options{Offline: true, DependencyFile: file}).Scan(file); err == nil {
		t.Fatal("two selected inventories accepted")
	}
}

func TestUnresolvedInventoryFailsBeforeNetworkButCanBeInspectedOffline(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "npm-shrinkwrap.json")
	if err := os.WriteFile(file, []byte(`{"lockfileVersion":3,"packages":{"node_modules/private":{"version":"1.0.0","resolved":"https://secret.invalid/tarball"}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := New(Options{CheckIDs: []string{"CVE-001"}}).Scan(file); err == nil {
		t.Fatal("unresolved identity queried/ignored")
	}
	r, _, err := New(Options{Offline: true}).Scan(file)
	if err != nil || r.Dependencies == nil || r.Dependencies.Packages[0].Unresolved == "" {
		t.Fatalf("offline inspection lost unknown: %v %+v", err, r)
	}
}

func TestDirectoryDoesNotImplicitlyTransmitLockNames(t *testing.T) {
	dir := t.TempDir()
	lock := filepath.Join(dir, "package-lock.json")
	if err := os.WriteFile(filepath.Join(dir, "server.js"), []byte("export const server = {};"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lock, []byte(`{"lockfileVersion":3,"packages":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	r, _, err := New(Options{CheckIDs: []string{"CVE-001"}}).Scan(dir)
	if err != nil || r.Dependencies != nil || r.Coverage.Advisories != "skipped" {
		t.Fatalf("unexpected implicit advisory inventory: %v %+v", err, r)
	}
	r, _, err = New(Options{DependencyFile: lock, Offline: true}).Scan(dir)
	if err != nil || r.Dependencies == nil {
		t.Fatalf("explicit directory inclusion failed: %v", err)
	}
}
