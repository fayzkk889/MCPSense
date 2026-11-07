package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/fayzkk889/MCPSense/internal/nodebridge"
	"github.com/fayzkk889/MCPSense/internal/utils"
	"github.com/pelletier/go-toml/v2"
	"github.com/spf13/cobra"
)

func mcpSetupCmd(install bool) *cobra.Command {
	client, root, config := "generic", ".", ""
	network, execute, private, write := false, false, false, false
	use, short := "config", "Print a client configuration for this exact installed CLI/MCP version"
	if install {
		use, short = "install", "Add MCPSense to a client while preserving its existing MCP servers and settings"
	}
	command := &cobra.Command{Use: use, Short: short, Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		absolute, err := nodebridge.Abs(root)
		if err != nil {
			return err
		}
		absolute, err = nodebridge.RealPath(absolute)
		if err != nil {
			return fmt.Errorf("root must be an existing project directory")
		}
		info, err := os.Stat(absolute)
		if err != nil || !info.IsDir() {
			return fmt.Errorf("root must be an existing project directory")
		}
		if (execute || private) && !network {
			return fmt.Errorf("live execution and private endpoints also require --allow-network")
		}
		program, args, platform, err := mcpLaunchInfo()
		if err != nil {
			return err
		}
		args = append(args, "mcp", "serve", "--root", absolute)
		for _, option := range []struct {
			enabled bool
			flag    string
		}{
			{network, "--allow-network"}, {execute, "--allow-exec"}, {private, "--allow-private-network"}, {write, "--allow-write"},
		} {
			if option.enabled {
				args = append(args, option.flag)
			}
		}
		entry := map[string]interface{}{"command": program, "args": args}
		key := "mcpServers"
		switch client {
		case "generic", "cursor", "claude-desktop", "claude-code":
		case "vscode":
			key = "servers"
			entry["type"] = "stdio"
		case "codex":
			key = "mcp_servers"
		default:
			return fmt.Errorf("client must be cursor, vscode, claude-code, claude-desktop, codex or generic")
		}
		if !install {
			if client == "codex" {
				encoded, err := toml.Marshal(map[string]interface{}{key: map[string]interface{}{"mcpsense": entry}})
				if err != nil {
					return err
				}
				_, err = cmd.OutOrStdout().Write(encoded)
				return err
			}
			encoder := json.NewEncoder(cmd.OutOrStdout())
			encoder.SetIndent("", "  ")
			return encoder.Encode(map[string]interface{}{key: map[string]interface{}{"mcpsense": entry}})
		}
		if config == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return err
			}
			switch client {
			case "cursor":
				config = filepath.Join(home, ".cursor", "mcp.json")
			case "vscode":
				config = filepath.Join(absolute, ".vscode", "mcp.json")
			case "claude-code":
				config = filepath.Join(absolute, ".mcp.json")
			case "codex":
				codexHome := managementEnv("CODEX_HOME")
				if codexHome == "" {
					codexHome = filepath.Join(home, ".codex")
				}
				config = filepath.Join(codexHome, "config.toml")
			case "claude-desktop":
				switch platform {
				case "win32", "windows":
					appdata := managementEnv("APPDATA")
					if appdata == "" {
						return fmt.Errorf("APPDATA unavailable; pass --config explicitly")
					}
					config = filepath.Join(appdata, "Claude", "claude_desktop_config.json")
				case "darwin":
					config = filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json")
				default:
					return fmt.Errorf("pass the actual Claude Desktop --config path on this platform")
				}
			default:
				return fmt.Errorf("generic installation needs an explicit --config path")
			}
		}
		config, err = nodebridge.Abs(config)
		if err != nil {
			return err
		}
		backup, changed, err := installMCPConfig(config, key, entry, client == "codex")
		if err != nil {
			return err
		}
		if changed {
			fmt.Fprintf(cmd.OutOrStdout(), "Connected MCPSense %s in %s\n", version, config)
		} else {
			fmt.Fprintln(cmd.OutOrStdout(), "MCPSense already has this configuration.")
		}
		if backup != "" {
			fmt.Fprintf(cmd.OutOrStdout(), "Original configuration backup: %s\n", backup)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Approved project: %s\nRestart the client, approve the mcpsense connection, then ask: Check my MCP configuration.\n", absolute)
		fmt.Fprintln(cmd.OutOrStdout(), "CLI and MCP use this same installed engine. After mcpsense update, restart the MCP connection to load the new release.")
		return nil
	}}
	command.Flags().StringVar(&client, "client", "generic", "cursor, vscode, claude-code, claude-desktop, codex or generic")
	command.Flags().StringVar(&root, "root", ".", "Project directory the assistant is permitted to inspect")
	if install {
		command.Flags().StringVar(&config, "config", "", "Override the client's configuration file path")
	}
	command.Flags().BoolVar(&network, "allow-network", false, "Grant optional live metadata and OSV advisory lookups")
	command.Flags().BoolVar(&execute, "allow-exec", false, "Grant optional execution of explicitly selected MCP programs")
	command.Flags().BoolVar(&private, "allow-private-network", false, "Grant optional private/loopback endpoints")
	command.Flags().BoolVar(&write, "allow-write", false, "Grant explicit report exports and reviewed baseline changes")
	return command
}

// installMCPConfig serializes our installers with an exclusive lock, validates
// existing settings and keeps an exact private backup before atomic replacement.
// Codex settings are appended so comments and all existing TOML remain intact.
func installMCPConfig(path, key string, entry map[string]interface{}, isTOML bool) (backup string, changed bool, err error) {
	if err = nodebridge.MkdirAll(nodebridge.Dir(path), 0700); err != nil {
		return "", false, err
	}
	lockPath := path + ".mcpsense.lock"
	lock, err := os.OpenFile(lockPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", false, fmt.Errorf("configuration is locked by another setup; retry after it completes")
	}
	defer func() { _ = lock.Close(); _ = os.Remove(lockPath) }()
	original, readErr := utils.ReadBounded(path, 4<<20)
	exists := readErr == nil
	if readErr != nil && !os.IsNotExist(readErr) {
		return "", false, fmt.Errorf("client configuration is not a readable regular file")
	}
	if _, statErr := os.Lstat(path); !exists && !os.IsNotExist(statErr) {
		return "", false, fmt.Errorf("client configuration must be a regular non-symlink file")
	}
	var document map[string]interface{}
	if exists {
		if isTOML {
			err = toml.Unmarshal(original, &document)
		} else {
			err = json.Unmarshal(original, &document)
		}
		if err != nil || document == nil {
			return "", false, fmt.Errorf("existing client configuration is invalid; it was preserved. Use mcp config for a manual snippet")
		}
	} else {
		document = map[string]interface{}{}
	}
	servers := map[string]interface{}{}
	if value, ok := document[key]; ok {
		var valid bool
		servers, valid = value.(map[string]interface{})
		if !valid {
			return "", false, fmt.Errorf("existing server section is invalid; configuration preserved")
		}
	}
	if value, ok := servers["mcpsense"]; ok {
		before, _ := json.Marshal(value)
		after, _ := json.Marshal(entry)
		if bytes.Equal(before, after) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("a different mcpsense entry already exists; review it before replacing it. Use mcp config to see the proposed entry")
	}
	var data []byte
	if isTOML {
		addition, encodeErr := toml.Marshal(entry)
		if encodeErr != nil {
			return "", false, encodeErr
		}
		data = append(append([]byte{}, original...), []byte("\n[mcp_servers.mcpsense]\n")...)
		data = append(data, addition...)
		var verified map[string]interface{}
		if toml.Unmarshal(data, &verified) != nil {
			return "", false, fmt.Errorf("cannot append a valid Codex server table; configuration preserved")
		}
		// Reject unusual inline tables that cannot be extended without changing
		// their surrounding syntax, rather than rewriting the user's settings.
		servers["mcpsense"] = entry
		document[key] = servers
		wanted, _ := json.Marshal(document)
		actual, _ := json.Marshal(verified)
		if !bytes.Equal(wanted, actual) {
			return "", false, fmt.Errorf("Codex settings would change outside the server entry; configuration preserved")
		}
	} else {
		servers["mcpsense"] = entry
		document[key] = servers
		data, err = json.MarshalIndent(document, "", "  ")
		if err != nil {
			return "", false, err
		}
		data = append(data, '\n')
	}
	temp, err := os.CreateTemp(nodebridge.Dir(path), ".mcpsense-config-*")
	if err != nil {
		return "", false, err
	}
	tempName := temp.Name()
	defer func() { _ = os.Remove(tempName) }()
	if _, err = temp.Write(data); err != nil {
		_ = temp.Close()
		return "", false, err
	}
	if err = temp.Close(); err != nil {
		return "", false, err
	}
	if exists {
		current, currentErr := utils.ReadBounded(path, 4<<20)
		if currentErr != nil || !bytes.Equal(original, current) {
			return "", false, fmt.Errorf("client settings changed during setup; retry with the current file")
		}
		saved, saveErr := os.CreateTemp(nodebridge.Dir(path), ".mcpsense-original-*")
		if saveErr != nil {
			return "", false, saveErr
		}
		backup = saved.Name()
		_, writeErr := saved.Write(original)
		closeErr := saved.Close()
		if writeErr != nil || closeErr != nil {
			return backup, false, fmt.Errorf("could not complete configuration backup")
		}
	} else {
		// Reserve a new destination without replacing a file created by an editor.
		placeholder, createErr := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if createErr != nil {
			return "", false, fmt.Errorf("client settings appeared during setup; retry")
		}
		if closeErr := placeholder.Close(); closeErr != nil {
			return "", false, closeErr
		}
	}
	if err = os.Rename(tempName, path); err != nil {
		return backup, false, fmt.Errorf("could not replace the client configuration; close the client and retry: %w", err)
	}
	return backup, true, nil
}
