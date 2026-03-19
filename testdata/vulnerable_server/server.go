package main

// This file intentionally contains security vulnerabilities for testing mcpsense.
// Do NOT use this code in production.

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
)

// ToolInput represents tool invocation parameters.
type ToolInput struct {
	Command string
	URL     string
	Path    string
	Query   string
}

// RunCommand executes an arbitrary shell command from tool input.
// VULNERABILITY: Command injection via exec.Command with "sh" shell.
func RunCommand(input ToolInput) (string, error) {
	// VULN SEC-002, SEC-007: User input interpolated into shell command.
	cmd := exec.Command("sh", "-c", input.Command)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// RunCommandSprintf also injects via fmt.Sprintf.
// VULNERABILITY: Command injection via string interpolation.
func RunCommandSprintf(userInput string) (string, error) {
	// VULN SEC-007: fmt.Sprintf used to build command argument.
	cmd := exec.Command("sh", "-c", fmt.Sprintf("grep -r %s /var/log", userInput))
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// FetchURL fetches a URL without any domain validation.
// VULNERABILITY: SSRF via unchecked URL parameter.
func FetchURL(input ToolInput) (string, error) {
	// VULN SEC-003: No allowlist check before HTTP request.
	resp, err := http.Get(input.URL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	return string(buf[:n]), nil
}

// ReadFile reads a file by path without path validation.
// VULNERABILITY: Path traversal and data exfiltration.
func ReadFile(input ToolInput) (string, error) {
	// VULN SEC-004, SEC-008: No path sanitization, raw file contents returned.
	data, err := os.ReadFile(input.Path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func main() {
	fmt.Println("Vulnerable MCP server started (for testing only)")
}
