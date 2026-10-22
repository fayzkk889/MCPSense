package cve

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type fakeTransport func(*http.Request) (*http.Response, error)

func (f fakeTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestLaterAdvisoryFailureNotClean(t *testing.T) {
	t.Setenv("USERPROFILE", t.TempDir())
	t.Setenv("HOME", t.TempDir())
	calls := 0
	c := &Client{http: &http.Client{Transport: fakeTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		if calls == 2 {
			return nil, errors.New("synthetic offline")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"vulns":[]}`)), Header: make(http.Header)}, nil
	})}}
	if _, ok := c.CheckAll([]Package{{Name: "one", Ecosystem: "npm"}, {Name: "two", Ecosystem: "npm"}}); ok || calls != 2 {
		t.Fatalf("later failure hidden: ok=%v calls=%d", ok, calls)
	}
}
