//go:build js && wasm

package main

import (
	"context"
	"fmt"
	"github.com/fayzkk889/MCPSense/internal/netpolicy"
	"github.com/fayzkk889/MCPSense/internal/nodebridge"
	"net/http"
	"net/netip"
	"syscall/js"
)

func validateRuntime() error {
	h := nodebridge.Host()
	if h.Type() != js.TypeObject || h.Get("sourceHash").Type() != js.TypeString || h.Get("sourceHash").String() != nodebridge.HostSourceHash() {
		return fmt.Errorf("npm runtime components do not match; reinstall the reviewed package")
	}
	return nil
}

func init() {
	http.DefaultTransport = &nodebridge.Transport{Allowed: func(ip netip.Addr) bool { return netpolicy.Allowed(ip, false) }}
}

func commandContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	cb := js.FuncOf(func(js.Value, []js.Value) interface{} { cancel(); return nil })
	nodebridge.Host().Call("setSignalHandler", cb)
	return ctx, func() { nodebridge.Host().Call("clearSignalHandler"); cb.Release(); cancel() }
}
