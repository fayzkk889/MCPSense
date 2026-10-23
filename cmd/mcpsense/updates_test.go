package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPublishedVersionChannels(t *testing.T) {
	for _, tc := range []struct {
		name, github, npm string
		status            int
		wantError         bool
	}{
		{"aligned", `{"tag_name":"v0.4.0"}`, `{"version":"0.4.0"}`, 200, false},
		{"drift visible", `{"tag_name":"v0.4.0"}`, `{"version":"0.3.0"}`, 200, false},
		{"prerelease", `{"tag_name":"v0.4.0-rc1","prerelease":true}`, `{"version":"0.4.0"}`, 200, true},
		{"missing tag", `{}`, `{"version":"0.4.0"}`, 200, true},
		{"bad JSON", `{broken`, `{}`, 200, true},
		{"oversized", strings.Repeat(" ", 65537), `{}`, 200, true},
		{"unavailable", `{}`, `{}`, 503, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				if r.URL.Path == "/github" {
					w.Write([]byte(tc.github))
				} else {
					w.Write([]byte(tc.npm))
				}
			}))
			defer server.Close()
			github, npm, err := publishedVersions(context.Background(), server.Client(), server.URL+"/github", server.URL+"/npm")
			if (err != nil) != tc.wantError {
				t.Fatalf("unexpected error %v", err)
			}
			if err == nil && tc.name == "drift visible" && github == npm {
				t.Fatal("channel drift hidden")
			}
		})
	}
}

func TestPlainVersionStaysOfflineAndExact(t *testing.T) {
	cmd := newVersionCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if out.String() != "mcpsense v"+version+"\n" {
		t.Fatal(out.String())
	}
}
