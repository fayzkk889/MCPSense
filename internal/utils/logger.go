package utils

import (
	"fmt"
	"io"
	"os"
	"time"
)

// LogLevel defines logging verbosity.
type LogLevel int

const (
	LogLevelDebug LogLevel = iota
	LogLevelInfo
	LogLevelWarn
	LogLevelError
	LogLevelSilent
)

// Logger provides structured logging for mcpsense.
type Logger struct {
	level  LogLevel
	output io.Writer
}

// NewLogger creates a new Logger writing to stderr at the given level.
func NewLogger(level LogLevel) *Logger {
	return &Logger{level: level, output: os.Stderr}
}

// NewLoggerWithWriter creates a Logger writing to the given writer.
func NewLoggerWithWriter(level LogLevel, w io.Writer) *Logger {
	return &Logger{level: level, output: w}
}

func (l *Logger) log(level string, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(l.output, "%s [%s] %s\n", time.Now().Format("15:04:05"), level, msg)
}

// Debug logs a debug-level message.
func (l *Logger) Debug(format string, args ...interface{}) {
	if l.level <= LogLevelDebug {
		l.log("DEBUG", format, args...)
	}
}

// Info logs an info-level message.
func (l *Logger) Info(format string, args ...interface{}) {
	if l.level <= LogLevelInfo {
		l.log("INFO", format, args...)
	}
}

// Warn logs a warning-level message.
func (l *Logger) Warn(format string, args ...interface{}) {
	if l.level <= LogLevelWarn {
		l.log("WARN", format, args...)
	}
}

// Error logs an error-level message.
func (l *Logger) Error(format string, args ...interface{}) {
	if l.level <= LogLevelError {
		l.log("ERROR", format, args...)
	}
}
