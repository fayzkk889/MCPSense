//go:build !js

package main

import (
	"os"
	"runtime"
)

func mcpLaunchInfo() (string, []string, string, error) {
	executable, err := os.Executable()
	return executable, []string{}, runtime.GOOS, err
}
