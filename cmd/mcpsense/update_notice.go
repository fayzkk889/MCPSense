package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/fayzkk889/MCPSense/internal/nodebridge"
	"github.com/spf13/cobra"
)

type noticeCache struct {
	Checked time.Time `json:"checked_at"`
	Latest  string    `json:"latest_version,omitempty"`
}
type noticeOptions struct {
	Current, File, GitHub, Npm string
	Now                        time.Time
	Client                     *http.Client
}

func cachedUpdateNotice(ctx context.Context, out io.Writer, o noticeOptions) {
	if _, err := compareStable(o.Current, o.Current); err != nil {
		return
	}
	var cached noticeCache
	if f, err := os.Open(o.File); err == nil {
		data, e := io.ReadAll(io.LimitReader(f, 4097))
		_ = f.Close()
		if e == nil && len(data) <= 4096 {
			_ = json.Unmarshal(data, &cached)
		}
	}
	validTime := !cached.Checked.IsZero() && !cached.Checked.After(o.Now.Add(time.Minute))
	if !validTime || o.Now.Sub(cached.Checked) >= time.Hour {
		github, npm, err := publishedVersions(ctx, o.Client, o.GitHub, o.Npm)
		cached = noticeCache{Checked: o.Now}
		if err == nil && github == npm {
			if _, e := compareStable(github, github); e == nil {
				cached.Latest = github
			}
		}
		// Optional cache I/O cannot change the scan's result or exit status.
		if nodebridge.MkdirAll(nodebridge.Dir(o.File), 0700) == nil {
			if f, e := os.CreateTemp(nodebridge.Dir(o.File), "updates-*.json"); e == nil {
				tmp := f.Name()
				e = json.NewEncoder(f).Encode(cached)
				closeErr := f.Close()
				if e == nil && closeErr == nil {
					_ = os.Rename(tmp, o.File)
				}
				_ = os.Remove(tmp)
			}
		}
	}
	if order, e := compareStable(o.Current, cached.Latest); e == nil && order < 0 {
		fmt.Fprintf(out, "MCPSense update available: %s → %s. Run mcpsense update.\n", o.Current, cached.Latest)
	}
}

func maybeAnnounceUpdate(cmd *cobra.Command, offline bool, format string) {
	disabled, _ := cmd.Flags().GetBool("no-update-check")
	if offline || format != "cli" || disabled || managementEnv("MCPSENSE_NO_UPDATE_CHECK") == "1" || managementEnv("CI") != "" || !managementInteractive() {
		return
	}
	base, err := managementCacheDir()
	if err != nil {
		return
	}
	file, err := nodebridge.Abs(filepath.Join(base, "mcpsense", "updates.json"))
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(cmd.Context(), 2*time.Second)
	defer cancel()
	cachedUpdateNotice(ctx, cmd.ErrOrStderr(), noticeOptions{version, file, githubLatest, npmLatest, time.Now(), versionClient(2 * time.Second)})
}
