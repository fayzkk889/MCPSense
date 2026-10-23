package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

const githubLatest = "https://api.github.com/repos/fayzkk889/MCPSense/releases/latest"
const npmLatest = "https://registry.npmjs.org/mcpsense/latest"

var stableVersion = regexp.MustCompile(`^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

type publishedVersion struct {
	Version    string `json:"version"`
	Tag        string `json:"tag_name"`
	Draft      bool   `json:"draft"`
	Prerelease bool   `json:"prerelease"`
}

func fetchVersion(ctx context.Context, client *http.Client, address string) (publishedVersion, error) {
	var version publishedVersion
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return version, err
	}
	req.Header.Set("User-Agent", "mcpsense-version-check")
	req.Header.Set("Accept", "application/json")
	response, err := client.Do(req)
	if err != nil {
		return version, fmt.Errorf("published-version lookup unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return version, fmt.Errorf("published-version lookup returned HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 65537))
	if err != nil || len(body) > 65536 {
		return version, fmt.Errorf("invalid published-version response")
	}
	if err = json.Unmarshal(body, &version); err != nil {
		return version, fmt.Errorf("invalid published-version JSON")
	}
	return version, nil
}

func publishedVersions(ctx context.Context, client *http.Client, githubURL, npmURL string) (string, string, error) {
	release, err := fetchVersion(ctx, client, githubURL)
	if err != nil {
		return "", "", fmt.Errorf("GitHub: %w", err)
	}
	npm, err := fetchVersion(ctx, client, npmURL)
	if err != nil {
		return "", "", fmt.Errorf("npm: %w", err)
	}
	if release.Draft || release.Prerelease || !stableVersion.MatchString(release.Tag) || !stableVersion.MatchString(npm.Version) {
		return "", "", fmt.Errorf("published channels did not return valid stable versions")
	}
	return strings.TrimPrefix(release.Tag, "v"), strings.TrimPrefix(npm.Version, "v"), nil
}

func newVersionCmd() *cobra.Command {
	check := false
	cmd := &cobra.Command{Use: "version", Short: "Print installed version; --check compares published GitHub and npm versions", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Fprintf(cmd.OutOrStdout(), "mcpsense v%s\n", version)
		if !check {
			return nil
		}
		// Networking is explicit, bounded, and never performed during ordinary
		// version/startup/offline scans. No project contents or credentials are sent.
		client := &http.Client{Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return fmt.Errorf("redirect rejected") }}
		github, npm, err := publishedVersions(cmd.Context(), client, githubLatest, npmLatest)
		if err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Latest published GitHub release: %s\nLatest npm version: %s\n", github, npm)
		if github != npm {
			return fmt.Errorf("release channels disagree; review https://github.com/fayzkk889/MCPSense/releases before updating")
		}
		if version == github {
			fmt.Fprintln(cmd.OutOrStdout(), "Installed version matches both published channels.")
			return nil
		}
		fmt.Fprintln(cmd.OutOrStdout(), "Installed version differs from the published stable release. A development checkout may be newer.")
		fmt.Fprintln(cmd.OutOrStdout(), "To select the published stable release, use one route:")
		fmt.Fprintln(cmd.OutOrStdout(), "  npm install -g mcpsense@latest")
		fmt.Fprintln(cmd.OutOrStdout(), "  go install github.com/fayzkk889/MCPSense/cmd/mcpsense@latest")
		return nil
	}}
	cmd.Flags().BoolVar(&check, "check", false, "Contact GitHub and npm to compare published stable versions (no automatic update)")
	return cmd
}
