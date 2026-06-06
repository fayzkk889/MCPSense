package drift

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// StoreDir returns the directory where snapshots are stored: ~/.mcpsense/snapshots/
func StoreDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("could not determine home directory: %w", err)
	}
	return filepath.Join(home, ".mcpsense", "snapshots"), nil
}

// DefaultPath returns the default snapshot path for a given scan target.
func DefaultPath(target string) (string, error) {
	dir, err := StoreDir()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(target))
	name := hex.EncodeToString(sum[:]) + ".json"
	return filepath.Join(dir, name), nil
}

// Exists reports whether a snapshot file exists at the given path.
func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// Load reads a snapshot from disk.
func Load(path string) (*Snapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading baseline %q: %w", path, err)
	}
	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("parsing baseline %q: %w", path, err)
	}
	return &snap, nil
}

// Save writes a snapshot to disk, creating the directory if needed.
func Save(path string, snap *Snapshot) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("creating snapshot directory: %w", err)
	}
	data, err := MarshalSnapshot(snap)
	if err != nil {
		return fmt.Errorf("serializing snapshot: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("writing snapshot %q: %w", path, err)
	}
	return nil
}
