//go:build js && wasm

package main

import (
	"fmt"
	"github.com/spf13/cobra"
	"syscall/js"
)

func managementEnv(name string) string {
	v := js.Global().Get("process").Get("env").Get(name)
	if v.Type() == js.TypeString {
		return v.String()
	}
	return ""
}
func managementInteractive() bool {
	p := js.Global().Get("process")
	a, b := p.Get("stdout").Get("isTTY"), p.Get("stderr").Get("isTTY")
	return a.Type() == js.TypeBoolean && a.Bool() && b.Type() == js.TypeBoolean && b.Bool()
}
func managementCacheDir() (string, error) {
	p := js.Global().Get("process")
	if p.Get("platform").String() == "win32" {
		if s := managementEnv("LOCALAPPDATA"); s != "" {
			return s, nil
		}
	}
	if s := managementEnv("XDG_CACHE_HOME"); s != "" {
		return s, nil
	}
	if s := managementEnv("HOME"); s != "" {
		return s + "/.cache", nil
	}
	return "", fmt.Errorf("no user cache")
}
func performPlatformUpdate(cmd *cobra.Command, plan updatePlan, repair bool) error {
	return fmt.Errorf("run update through the installed npm mcpsense entrypoint")
}
