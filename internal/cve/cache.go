package cve

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

const (
	cacheTTL      = 24 * time.Hour
	cachePruneAge = 7 * 24 * time.Hour
)

type cacheEntry struct {
	FetchedAt time.Time `json:"fetched_at"`
	Vulns     []Vuln    `json:"vulns"`
}

func cacheDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".mcpsense", "cve-cache"), nil
}

func cacheKey(pkg Package) string {
	sum := sha256.Sum256([]byte(pkg.Ecosystem + "|" + pkg.Name + "|" + pkg.Version))
	return hex.EncodeToString(sum[:]) + ".json"
}

// loadCache returns (vulns, fresh, found). fresh is false if the entry is stale.
func loadCache(pkg Package) (vulns []Vuln, fresh bool, found bool) {
	dir, err := cacheDir()
	if err != nil {
		return nil, false, false
	}
	path := filepath.Join(dir, cacheKey(pkg))
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false, false
	}
	var entry cacheEntry
	if json.Unmarshal(data, &entry) != nil {
		return nil, false, false
	}
	fresh = time.Since(entry.FetchedAt) < cacheTTL
	return entry.Vulns, fresh, true
}

func saveCache(pkg Package, vulns []Vuln) {
	dir, err := cacheDir()
	if err != nil {
		return
	}
	_ = os.MkdirAll(dir, 0o755)
	entry := cacheEntry{FetchedAt: time.Now().UTC(), Vulns: vulns}
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(dir, cacheKey(pkg)), data, 0o600)
}

// PruneCache deletes cache files older than cachePruneAge. Best-effort, silent.
func PruneCache() {
	dir, err := cacheDir()
	if err != nil {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-cachePruneAge)
	for _, e := range entries {
		info, err := e.Info()
		if err == nil && info.ModTime().Before(cutoff) {
			_ = os.Remove(filepath.Join(dir, e.Name()))
		}
	}
}
