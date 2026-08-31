package cli

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"ssl-update/internal/config"
)

func parseLevel(s string) slog.Level {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// setupLogger creates a slog.Logger writing to cfg.Log.File (or stdout/stderr
// if empty) and sets it as the default. Returns a Closer for the file
// (or nil if not file-based); caller must Close it after use.
func setupLogger(cfg config.LogConfig, overrideLevel, overrideFormat string) (*slog.Logger, io.Closer, error) {
	level := cfg.Level
	if overrideLevel != "" {
		level = overrideLevel
	}
	format := cfg.Format
	if overrideFormat != "" {
		format = overrideFormat
	}

	var w io.Writer = os.Stderr
	var closer io.Closer
	if cfg.File != "" {
		f, err := os.OpenFile(cfg.File, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, nil, fmt.Errorf("open log file %s: %w", cfg.File, err)
		}
		w = f
		closer = f
	}

	opts := &slog.HandlerOptions{Level: parseLevel(level)}
	var h slog.Handler
	if format == "json" {
		h = slog.NewJSONHandler(w, opts)
	} else {
		h = slog.NewTextHandler(w, opts)
	}
	logger := slog.New(h)
	slog.SetDefault(logger)
	return logger, closer, nil
}
