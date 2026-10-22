package scanner

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestExplicitLoopbackAndRedirectPolicy(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{}}}`)
	}))
	defer server.Close()
	if _, _, err := New(Options{Mode: ModeLive, DisableCVE: true}).Scan(server.URL); err == nil || calls != 0 {
		t.Fatal("private endpoint contacted without permission")
	}
	if _, _, err := New(Options{Mode: ModeLive, DisableCVE: true, AllowPrivateNetwork: true}).Scan(server.URL); err != nil || calls != 1 {
		t.Fatalf("explicit local endpoint failed: %v calls=%d", err, calls)
	}
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, server.URL, http.StatusFound) }))
	defer redirect.Close()
	if _, _, err := New(Options{Mode: ModeLive, DisableCVE: true, AllowPrivateNetwork: true}).Scan(redirect.URL); err == nil || calls != 1 {
		t.Fatal("redirect followed or failure hidden")
	}
}

func TestAddressPolicy(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "10.0.0.1", "::1", "::ffff:127.0.0.1"} {
		a := netip.MustParseAddr(ip)
		if allowedAddress(a, false) || !allowedAddress(a, true) {
			t.Fatalf("invalid private-address policy for %s", ip)
		}
	}
	for _, ip := range []string{"169.254.169.254", "169.254.170.2", "0.0.0.0", "fe80::1", "224.0.0.1", "100.100.100.200", "192.0.2.1", "64:ff9b::a9fe:a9fe"} {
		if allowedAddress(netip.MustParseAddr(ip), true) {
			t.Fatalf("unsafe address accepted: %s", ip)
		}
	}
	if !allowedAddress(netip.MustParseAddr("1.1.1.1"), false) {
		t.Fatal("public address rejected")
	}
	for _, target := range []string{"https://user:password@example.invalid/mcp", "https://example.invalid/#fragment", "file:///etc/passwd"} {
		if _, err := liveClient(target, false); err == nil {
			t.Fatal("unsafe URL accepted")
		}
	}
}
