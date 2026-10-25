//go:build js && wasm

package scanner

import (
	"context"
	"github.com/fayzkk889/MCPSense/internal/nodebridge"
	"io"
)

func startStdioProcess(ctx context.Context, parts []string) (io.WriteCloser, io.ReadCloser, func(), error) {
	return nodebridge.StartProcess(ctx, parts)
}
