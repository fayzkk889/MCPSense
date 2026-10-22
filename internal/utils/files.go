package utils

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// SupportedExtensions lists the source file extensions that mcpsense analyzes.
var SupportedExtensions = []string{".go", ".py", ".ts", ".js"}

const MaxInputBytes = 4 << 20
const MaxScanBytes = 64 << 20

func SkipDirectory(name string) bool {
	return name == "vendor" || name == "node_modules" || name == ".git" || name == "__pycache__" || name == "dist" || name == "build" || name == "bin"
}

// ReadInput rejects special files and symlinks and bounds even a growing file.
// It is not filesystem isolation against concurrent local path replacement.
func ReadInput(path string) ([]byte, error) {
	return ReadBounded(path, MaxInputBytes)
}
func ReadBounded(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("scan input must be a regular non-symlink file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("input exceeds %d byte file limit", limit)
	}
	return b, nil
}

// DiscoverSourceFiles walks the given directory and returns all source files
// with supported extensions mapped to their contents.
func DiscoverSourceFiles(root string) (map[string]string, error) {
	files := make(map[string]string)
	total := 0

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			// Skip common vendor/dependency directories.
			base := info.Name()
			if SkipDirectory(base) && path != root {
				return filepath.SkipDir
			}
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		for _, supported := range SupportedExtensions {
			if ext == supported {
				content, readErr := ReadInput(path)
				if readErr != nil {
					return readErr
				}
				files[path] = string(content)
				total += len(content)
				if total > MaxScanBytes || len(files) > 10000 {
					return fmt.Errorf("source scan budget exceeded")
				}
				break
			}
		}
		return nil
	})

	return files, err
}

// FindManifestFiles looks for MCP manifest/config files in the given directory.
func FindManifestFiles(root string) []string {
	candidates := []string{
		"mcp.json",
		"mcp-config.json",
		"mcpconfig.json",
		".mcp.json",
	}

	var found []string
	for _, candidate := range candidates {
		path := filepath.Join(root, candidate)
		if _, err := os.Stat(path); err == nil {
			found = append(found, path)
		}
	}

	// Also look one level deep.
	entries, err := os.ReadDir(root)
	if err != nil {
		return found
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		for _, candidate := range candidates {
			path := filepath.Join(root, entry.Name(), candidate)
			if _, err := os.Stat(path); err == nil {
				found = append(found, path)
			}
		}
	}
	return found
}

// ReadFile reads and returns the contents of a file.
func ReadFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// IsDirectory returns true if the given path is a directory.
func IsDirectory(path string) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	return info.IsDir(), nil
}

// FileExists returns true if a file or directory exists at the given path.
func FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
