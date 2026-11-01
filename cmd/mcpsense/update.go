package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

type updatePlan struct {
	Schema    int    `json:"schema_version"`
	Installed string `json:"installed_version"`
	Latest    string `json:"latest_version"`
	CheckOnly bool   `json:"check_only,omitempty"`
}

// Compare canonical stable components as decimal strings, without integer
// overflow or treating a development build as an older stable release.
func compareStable(a, b string) (int, error) {
	if len(a) > 64 || len(b) > 64 || !stableVersion.MatchString(a) || !stableVersion.MatchString(b) {
		return 0, fmt.Errorf("not a stable release version")
	}
	x, y := strings.Split(strings.TrimPrefix(a, "v"), "."), strings.Split(strings.TrimPrefix(b, "v"), ".")
	for i := range x {
		if len(x[i]) < len(y[i]) {
			return -1, nil
		}
		if len(x[i]) > len(y[i]) {
			return 1, nil
		}
		if x[i] < y[i] {
			return -1, nil
		}
		if x[i] > y[i] {
			return 1, nil
		}
	}
	return 0, nil
}

func versionClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return fmt.Errorf("redirect rejected") }}
}

func newUpdateCmd() *cobra.Command {
	var check, planJSON, repair bool
	cmd := &cobra.Command{Use: "update", Short: "Update the active installation and verify the command version", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		if !planJSON {
			fmt.Fprintln(cmd.ErrOrStderr(), "Checking published MCPSense releases...")
		}
		github, npm, err := publishedVersions(cmd.Context(), versionClient(8*time.Second), githubLatest, npmLatest)
		if err != nil {
			return err
		}
		if github != npm {
			return fmt.Errorf("release channels disagree; no update performed")
		}
		if _, err = compareStable(github, github); err != nil {
			return err
		}
		plan := updatePlan{Schema: 1, Installed: version, Latest: github, CheckOnly: check}
		if planJSON {
			return json.NewEncoder(cmd.OutOrStdout()).Encode(plan)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Installed: %s\nLatest stable: %s\n", version, github)
		if check {
			return nil
		}
		order, err := compareStable(version, github)
		if err != nil {
			return fmt.Errorf("unversioned/development build; select a published release using your installation command")
		}
		if order > 0 {
			return fmt.Errorf("installed version is newer than stable; refusing to downgrade")
		}
		return performPlatformUpdate(cmd, plan, repair)
	}}
	cmd.Flags().BoolVar(&check, "check", false, "Check published versions without changing files")
	cmd.Flags().BoolVar(&repair, "repair-path", false, "Repair an identified older installation shadowing this command")
	cmd.Flags().BoolVar(&planJSON, "plan-json", false, "Print the validated update plan for the npm entrypoint")
	_ = cmd.Flags().MarkHidden("plan-json")
	return cmd
}
