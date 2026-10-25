//go:build !js

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

func commandContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

func validateRuntime() error { return nil }
