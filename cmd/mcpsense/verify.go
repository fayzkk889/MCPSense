package main

import (
	"encoding/json"
	"fmt"
	"github.com/fayzkk889/MCPSense/internal/models"
	"github.com/fayzkk889/MCPSense/internal/utils"
	"github.com/spf13/cobra"
)

func readEvidence(path string) (*models.Report, error) {
	b, err := utils.ReadBounded(path, 16<<20)
	if err != nil || len(b) > 16<<20 {
		return nil, fmt.Errorf("verification report unreadable or oversized")
	}
	var r models.Report
	if json.Unmarshal(b, &r) != nil {
		return nil, fmt.Errorf("invalid verification JSON")
	}
	return &r, nil
}
func verifyCmd() *cobra.Command {
	return &cobra.Command{Use: "verify <before.json> <after.json>", Short: "Compare equivalent completed scans without network access", Args: cobra.ExactArgs(2), RunE: func(cmd *cobra.Command, args []string) error {
		before, err := readEvidence(args[0])
		if err != nil {
			return err
		}
		after, err := readEvidence(args[1])
		if err != nil {
			return err
		}
		result, err := models.VerifyReports(before, after)
		if err != nil {
			return err
		}
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	}}
}
