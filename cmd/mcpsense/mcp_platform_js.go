//go:build js && wasm

package main

import (
	"fmt"
	"strings"
	"syscall/js"
)

func mcpLaunchInfo() (string, []string, string, error) {
	process := js.Global().Get("process")
	entry := process.Get("argv").Index(1)
	if entry.Type() != js.TypeString {
		return "", nil, "", fmt.Errorf("run setup through the installed npm entrypoint")
	}
	if strings.Contains(strings.ReplaceAll(entry.String(), "\\", "/"), "/_npx/") {
		return "", nil, "", fmt.Errorf("setup from a temporary npx cache would pin an old copy; run npm install -g mcpsense@latest, then run mcpsense mcp install from that installation")
	}
	return process.Get("execPath").String(), []string{entry.String()}, process.Get("platform").String(), nil
}
