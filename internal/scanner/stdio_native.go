//go:build !js

package scanner

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"sync"
)

func startStdioProcess(ctx context.Context, parts []string) (io.WriteCloser, io.ReadCloser, func(), error) {
	childCtx, cancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(childCtx, parts[0], parts[1:]...)
	configureProcess(cmd)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		return nil, nil, nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		_ = stdin.Close()
		return nil, nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		cancel()
		_ = stdin.Close()
		_ = stdout.Close()
		return nil, nil, nil, fmt.Errorf("could not start authorized MCP server")
	}
	var once sync.Once
	stop := func() {
		once.Do(func() { cancel(); _ = stdin.Close(); _ = stdout.Close(); _ = cmd.Cancel(); _ = cmd.Wait() })
	}
	return stdin, stdout, stop, nil
}
