package utils

import (
	"os"
	"path/filepath"
	"strings"
)

// SupportedExtensions lists the source file extensions that mcpsense analyzes.
var SupportedExtensions = []string{".go", ".py", ".ts", ".js"}

// DiscoverSourceFiles walks the given directory and returns all source files
// with supported extensions mapped to their contents.
func DiscoverSourceFiles(root string) (map[string]string, error) {
	files := make(map[string]string)

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			// Skip common vendor/dependency directories.
			base := info.Name()
			if base == "vendor" || base == "node_modules" || base == ".git" || base == "__pycache__" || base == "dist" || base == "build" {
				return filepath.SkipDir
			}
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		for _, supported := range SupportedExtensions {
			if ext == supported {
				content, readErr := os.ReadFile(path)
				if readErr != nil {
					return readErr
				}
				files[path] = string(content)
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
