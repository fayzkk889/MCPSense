//go:build js && wasm

package nodebridge

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"syscall/js"
)

// Transport preserves the Go client's cancellation and redirect handling. DNS
// answers are checked in Go and pinned in Node's connection lookup callback.
type Transport struct{ Allowed func(netip.Addr) bool }

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL == nil || req.URL.User != nil || (req.URL.Scheme != "http" && req.URL.Scheme != "https") {
		return nil, fmt.Errorf("invalid runtime HTTP URL")
	}
	v, err := call(req.Context(), "lookup", req.URL.Hostname())
	if err != nil {
		return nil, fmt.Errorf("DNS resolution failed")
	}
	var addresses []string
	if json.Unmarshal([]byte(v.String()), &addresses) != nil || len(addresses) == 0 || len(addresses) > 64 {
		return nil, fmt.Errorf("invalid DNS response")
	}
	for _, s := range addresses {
		ip, err := netip.ParseAddr(s)
		if err != nil || t.Allowed == nil || !t.Allowed(ip) {
			return nil, fmt.Errorf("destination blocked by address policy")
		}
	}
	var body []byte
	if req.Body != nil {
		body, err = io.ReadAll(io.LimitReader(req.Body, (4<<20)+1))
		_ = req.Body.Close()
		if err != nil || len(body) > 4<<20 {
			return nil, fmt.Errorf("runtime HTTP request exceeds limit")
		}
	}
	bytes := js.Global().Get("Uint8Array").New(len(body))
	js.CopyBytesToJS(bytes, body)
	headers, _ := json.Marshal(req.Header)
	ips, _ := json.Marshal(addresses)
	v, err = call(req.Context(), "request", req.URL.String(), req.Method, string(headers), bytes, string(ips))
	if err != nil {
		return nil, err
	}
	responseBody := &Reader{ctx: req.Context(), id: v.Get("id").Int()}
	var raw []string
	if json.Unmarshal([]byte(v.Get("headers").String()), &raw) != nil || len(raw)%2 != 0 || len(raw) > 4096 {
		_ = responseBody.Close()
		return nil, fmt.Errorf("invalid runtime HTTP headers")
	}
	h := make(http.Header)
	for i := 0; i < len(raw); i += 2 {
		h.Add(raw[i], raw[i+1])
	}
	status := v.Get("status").Int()
	if status < 100 || status > 599 {
		_ = responseBody.Close()
		return nil, fmt.Errorf("invalid runtime HTTP status")
	}
	return &http.Response{StatusCode: status, Status: fmt.Sprintf("%d %s", status, http.StatusText(status)), Header: h, Body: responseBody, ContentLength: -1, Request: req}, nil
}
