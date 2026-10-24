package cve

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestPaginationDoesNotDropLaterAdvisories(t *testing.T) {
	calls := 0
	c := &Client{http: &http.Client{Transport: fakeTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		var body map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		response := `{"vulns":[{"id":"FIRST"}],"next_page_token":"page-two"}`
		if calls == 2 {
			if body["page_token"] != "page-two" || body["version"] != "1.0.0" {
				t.Fatalf("lost query identity: %v", body)
			}
			response = `{"vulns":[{"id":"FIRST"},{"id":"SECOND"}]}`
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(response))}, nil
	})}}
	got, err := c.queryOne(context.Background(), Package{Name: "fixture", Ecosystem: "npm", Version: "1.0.0"}, totalBudget)
	if err != nil || len(got) != 2 || calls != 2 {
		t.Fatalf("pagination incomplete: %v %v calls=%d", got, err, calls)
	}
}

func TestPaginationFailureAndCyclesAreNotCachedAsClean(t *testing.T) {
	for _, scenario := range []string{"later-error", "cycle", "page-limit", "bad-id", "malformed", "oversized", "null", "error-object"} {
		t.Run(scenario, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			t.Setenv("USERPROFILE", t.TempDir())
			calls := 0
			c := &Client{http: &http.Client{Transport: fakeTransport(func(*http.Request) (*http.Response, error) {
				calls++
				body := `{"vulns":[{"id":"ONE"}],"next_page_token":"again"}`
				if scenario == "later-error" && calls > 1 {
					return nil, errors.New("offline page two")
				}
				switch scenario {
				case "page-limit":
					body = fmt.Sprintf(`{"next_page_token":"page-%d"}`, calls)
				case "bad-id":
					body = `{"vulns":[{"summary":"missing ID"}]}`
				case "malformed":
					body = `{"vulns":`
				case "oversized":
					body = strings.Repeat(" ", (4<<20)+1)
				case "null":
					body = `null`
				case "error-object":
					body = `{"error":"synthetic service failure"}`
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body))}, nil
			})}}
			pkg := Package{Name: "fixture", Ecosystem: "npm", Version: "1.0.0"}
			if _, ok := c.Resolve(pkg); ok {
				t.Fatal("incomplete response accepted")
			}
			if _, _, found := loadCache(pkg); found {
				t.Fatal("partial response cached")
			}
		})
	}
}

func TestBoundedConcurrentDeduplicationPreservesEveryLocation(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", t.TempDir())
	var active, peak, calls atomic.Int32
	gate := make(chan struct{})
	c := &Client{http: &http.Client{Transport: fakeTransport(func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		n := active.Add(1)
		for old := peak.Load(); n > old; old = peak.Load() {
			if peak.CompareAndSwap(old, n) {
				break
			}
		}
		if n == maxWorkers {
			close(gate)
		}
		select {
		case <-gate:
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
		// Only close the gate during the initial wave.
		active.Add(-1)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"vulns":[{"id":"VULN"}]}`))}, nil
	})}}
	pkgs := []Package{}
	for i := 0; i < 16; i++ {
		pkgs = append(pkgs, Package{Name: fmt.Sprint("pkg", i%8), Version: "1.0.0", Ecosystem: "npm", Server: fmt.Sprint(i)})
	}
	got, ok := c.CheckAll(pkgs)
	if !ok || calls.Load() != 8 || peak.Load() != maxWorkers || len(got) != 16 {
		t.Fatalf("lost/doubled queries: ok=%v calls=%d peak=%d results=%d", ok, calls.Load(), peak.Load(), len(got))
	}
	for i := range got {
		if got[i].Package != pkgs[i] {
			t.Fatal("input order or component identity lost")
		}
	}
}

func TestCancellationAndOldCacheCannotProduceCleanResult(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", t.TempDir())
	c := &Client{http: &http.Client{Transport: fakeTransport(func(r *http.Request) (*http.Response, error) { <-r.Context().Done(); return nil, r.Context().Err() })}}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, ok := c.CheckAllContext(ctx, []Package{{Name: "x", Ecosystem: "npm"}}); ok {
		t.Fatal("cancellation marked complete")
	}
	pkg := Package{Name: "old-cache", Ecosystem: "npm"}
	dir, err := cacheDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	entry, _ := json.Marshal(map[string]interface{}{"fetched_at": time.Now().UTC(), "vulns": []Vuln{}})
	if err := os.WriteFile(filepath.Join(dir, cacheKey(pkg)), entry, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, found := loadCache(pkg); found {
		t.Fatal("pre-pagination cache trusted")
	}
}

func TestRedirectsAndAggregateBytesAreBounded(t *testing.T) {
	c := NewClient()
	if c.http.CheckRedirect == nil || c.http.CheckRedirect(nil, nil) != http.ErrUseLastResponse {
		t.Fatal("advisory POST redirects may disclose package identities")
	}
	ctx := context.WithValue(context.Background(), responseBudgetKey{}, new(atomic.Int64))
	if !consumeBudget(ctx, 64<<20) || consumeBudget(ctx, 1) {
		t.Fatal("scan byte budget not bounded")
	}
}

type fakeTransport func(*http.Request) (*http.Response, error)

func (f fakeTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestLaterAdvisoryFailureNotClean(t *testing.T) {
	t.Setenv("USERPROFILE", t.TempDir())
	t.Setenv("HOME", t.TempDir())
	var calls atomic.Int32
	c := &Client{http: &http.Client{Transport: fakeTransport(func(r *http.Request) (*http.Response, error) {
		if calls.Add(1) == 2 {
			return nil, errors.New("synthetic offline")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"vulns":[]}`)), Header: make(http.Header)}, nil
	})}}
	if _, ok := c.CheckAll([]Package{{Name: "one", Ecosystem: "npm"}, {Name: "two", Ecosystem: "npm"}}); ok || calls.Load() != 2 {
		t.Fatalf("later failure hidden: ok=%v calls=%d", ok, calls.Load())
	}
}
