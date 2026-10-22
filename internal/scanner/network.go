package scanner

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"time"
)

func allowedAddress(ip netip.Addr, private bool) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	if ip.IsPrivate() || ip.IsLoopback() {
		return private
	}
	for _, cidr := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001:db8::/32", "64:ff9b::/96", "64:ff9b:1::/48", "2002::/16", "2001::/32"} {
		if netip.MustParsePrefix(cidr).Contains(ip) {
			return false
		}
	}
	return ip.IsGlobalUnicast()
}
func liveClient(target string, private bool) (*http.Client, error) {
	u, err := url.Parse(target)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Fragment != "" {
		return nil, fmt.Errorf("invalid MCP URL; use an HTTP(S) endpoint without userinfo or fragment")
	}
	transport := http.DefaultTransport
	if base, ok := transport.(*http.Transport); ok {
		t := base.Clone()
		t.MaxResponseHeaderBytes = 64 << 10
		t.Proxy = nil
		t.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, fmt.Errorf("invalid MCP host")
			}
			addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
			if err != nil {
				return nil, fmt.Errorf("MCP DNS resolution failed")
			}
			if len(addresses) == 0 {
				return nil, fmt.Errorf("MCP host has no addresses")
			}
			for _, ip := range addresses {
				if !allowedAddress(ip, private) {
					return nil, fmt.Errorf("MCP destination is blocked; private/loopback addresses require --allow-private-network; link-local and metadata ranges remain blocked")
				}
			}
			var dialer net.Dialer
			dialer.Timeout = 10 * time.Second
			// Dial validated IPs directly, preventing a second DNS lookup after validation.
			for _, ip := range addresses {
				conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
				if err == nil {
					return conn, nil
				}
			}
			return nil, fmt.Errorf("MCP destination connection failed")
		}
		transport = t
	}
	return &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return fmt.Errorf("MCP redirects are disabled") }}, nil
}
