package main

import (
	"bytes"
	"os"
	"testing"
)

func TestFirstRunExamplePreservesFiles(t *testing.T) {
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Chdir(old); err != nil {
			t.Error(err)
		}
	}()
	cmd := rootCmd()
	var output bytes.Buffer
	cmd.SetOut(&output)
	cmd.SetArgs([]string{"init", "--example"})
	if err = cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile("mcp.json")
	if err != nil {
		t.Fatal(err)
	}
	cmd = rootCmd()
	cmd.SetArgs([]string{"scan", "./mcp.json", "--offline", "--no-baseline"})
	if err = cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	cmd = rootCmd()
	cmd.SetArgs([]string{"init", "--example"})
	if err = cmd.Execute(); err == nil {
		t.Fatal("existing target overwritten")
	}
	after, err := os.ReadFile("mcp.json")
	if err != nil || !bytes.Equal(original, after) {
		t.Fatal("target changed")
	}
}
