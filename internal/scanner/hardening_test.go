package scanner

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"
)

type fakeTransport func(*http.Request) (*http.Response, error)

func (f fakeTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestLiveHTTPFailuresPropagate(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
	}{{503, `{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"secret"}}`}, {200, `{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"secret"}}`}, {200, `{"jsonrpc":"2.0","id":999,"result":{}}`}, {200, `{"jsonrpc":"2.0","id":1,"result":null}`}} {
		client := &http.Client{Transport: fakeTransport(func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: tc.status, Body: io.NopCloser(strings.NewReader(tc.body)), Header: make(http.Header)}, nil
		})}
		if _, err := fetchManifestViaHTTP(client, "https://synthetic.invalid"); err == nil {
			t.Errorf("accepted failure: %+v", tc)
		}
	}
}
func TestStdioEOFIsFailure(t *testing.T) {
	if _, err := interrogateStdioServer(&bytes.Buffer{}, strings.NewReader("")); err == nil {
		t.Fatal("EOF accepted")
	}
}
func TestPolicyAndUnknownRulesBeforeSideEffects(t *testing.T) {
	old := http.DefaultTransport
	defer func() { http.DefaultTransport = old }()
	calls := 0
	http.DefaultTransport = fakeTransport(func(r *http.Request) (*http.Response, error) { calls++; return nil, io.EOF })
	for _, opts := range []Options{{Mode: ModeLive, Offline: true}, {Mode: ModeLive, CheckIDs: []string{"TYPO"}}, {Mode: ModeLive, ExcludeIDs: []string{"TYPO"}}} {
		if _, _, err := New(opts).Scan("https://synthetic.invalid"); err == nil {
			t.Fatal("policy accepted")
		}
	}
	if calls != 0 {
		t.Fatalf("policy made %d network calls", calls)
	}
	if _, _, err := New(Options{Mode: ModeLive}).Scan("synthetic-never-started command"); err == nil || !strings.Contains(err.Error(), "allow-exec") {
		t.Fatalf("execution permission not enforced: %v", err)
	}
}
