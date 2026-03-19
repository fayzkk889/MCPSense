package main

// This file demonstrates secure MCP server patterns.

import (
	"fmt"
	"path/filepath"
	"strings"
)

const allowedBaseDir = "/workspace/notes"

// allowedDomains lists the only domains the server may fetch from.
var allowedDomains = []string{"api.example.com", "data.example.com"}

// SearchInput holds validated search parameters.
type SearchInput struct {
	Query      string
	MaxResults int
}

// NoteInput holds validated note creation parameters.
type NoteInput struct {
	Title string
	Body  string
}

// FileInput holds a validated file path.
type FileInput struct {
	RelativePath string
}

// SafeReadNote reads a note file, validating the path stays within allowedBaseDir.
func SafeReadNote(input FileInput) (string, error) {
	// Sanitize path before file access.
	clean := filepath.Clean(filepath.Join(allowedBaseDir, input.RelativePath))
	if !strings.HasPrefix(clean, allowedBaseDir+"/") {
		return "", fmt.Errorf("access denied: path escapes workspace directory")
	}

	// In a real server, would read and return the note contents here.
	return fmt.Sprintf("contents of %s", clean), nil
}

// SafeFetchURL fetches a URL only if it is from an allowed domain.
func SafeFetchURL(rawURL string) (string, error) {
	// Validate against domain allowlist before any HTTP call.
	allowed := false
	for _, domain := range allowedDomains {
		if strings.Contains(rawURL, domain) {
			allowed = true
			break
		}
	}
	if !allowed {
		return "", fmt.Errorf("domain not in allowlist: %s", rawURL)
	}
	// Proceed with fetch (omitted for brevity).
	return "response data", nil
}

// SafeRunTask runs a parameterized task without shell invocation.
func SafeRunTask(taskName string, args []string) (string, error) {
	// Use exec.Command with explicit arguments, never via a shell interpreter.
	// exec.Command("/usr/local/bin/task-runner", append([]string{taskName}, args...)...)
	// Sanitized invocation ensures no shell injection is possible.
	return fmt.Sprintf("task %s completed with %d args", taskName, len(args)), nil
}

func main() {
	fmt.Println("Compliant MCP server started")
}
