//go:build js && wasm

package main

import (
	"context"
	"github.com/fayzkk889/MCPSense/internal/netpolicy"
	"github.com/fayzkk889/MCPSense/internal/nodebridge"
	"net/http"
	"net/netip"
	"syscall/js"
)

func init() {
	http.DefaultTransport = &nodebridge.Transport{Allowed: func(ip netip.Addr) bool { return netpolicy.Allowed(ip, false) }}
}

func commandContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	cb := js.FuncOf(func(js.Value, []js.Value) interface{} { cancel(); return nil })
	nodebridge.Host().Call("setSignalHandler", cb)
	return ctx, func() { nodebridge.Host().Call("clearSignalHandler"); cb.Release(); cancel() }
}
