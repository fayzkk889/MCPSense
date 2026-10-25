//go:build js && wasm

package scanner

import (
	"github.com/fayzkk889/MCPSense/internal/nodebridge"
	"net/http"
	"net/netip"
)

func liveRuntimeTransport(private bool) http.RoundTripper {
	return &nodebridge.Transport{Allowed: func(ip netip.Addr) bool { return allowedAddress(ip, private) }}
}
