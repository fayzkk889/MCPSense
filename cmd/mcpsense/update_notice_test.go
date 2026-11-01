package main

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStableVersionOrdering(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{{"0.4.9", "0.4.10", -1}, {"v0.4.5", "0.4.5", 0}, {"1.0.0", "0.99.999", 1}, {"99999999999999999999.0.0", "2.0.0", 1}} {
		got, err := compareStable(tc.a, tc.b)
		if err != nil || got != tc.want {
			t.Fatalf("%+v: %d %v", tc, got, err)
		}
	}
	for _, v := range []string{"dev", "0.4.5-rc1", "01.2.3", "1.2.3\x1b[0m", strings.Repeat("9", 65) + ".1.0"} {
		if _, e := compareStable(v, "0.4.5"); e == nil {
			t.Fatal(v)
		}
	}
}

func TestNoticeCacheAndFailureDoNotAuthorizeUpdates(t *testing.T) {
	requests := 0
	body := `{"tag_name":"v0.4.6","version":"0.4.6"}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests++; fmt.Fprint(w, body) }))
	defer server.Close()
	o := noticeOptions{"0.4.5", filepath.Join(t.TempDir(), "cache", "updates.json"), server.URL, server.URL, time.Now(), server.Client()}
	var out bytes.Buffer
	cachedUpdateNotice(context.Background(), &out, o)
	if requests != 2 || !strings.Contains(out.String(), "0.4.5 → 0.4.6") {
		t.Fatalf("%d %s", requests, &out)
	}
	out.Reset()
	cachedUpdateNotice(context.Background(), &out, o)
	if requests != 2 || !strings.Contains(out.String(), "mcpsense update") {
		t.Fatal(requests, out.String())
	}
	o.Now = o.Now.Add(2 * time.Hour)
	body = `{"tag_name":"v0.4.6","version":"0.4.7"}`
	out.Reset()
	cachedUpdateNotice(context.Background(), &out, o)
	if out.Len() != 0 {
		t.Fatal("channel mismatch announced an installable update")
	}
	if err := os.WriteFile(o.File, []byte(`{"checked_at":"2099-01-01T00:00:00Z","latest_version":"99.0.0\u001b[31m"}`), 0600); err != nil {
		t.Fatal(err)
	}
	body = `invalid`
	out.Reset()
	cachedUpdateNotice(context.Background(), &out, o)
	if out.Len() != 0 {
		t.Fatal("untrusted cache/failed lookup leaked a notice")
	}
}
