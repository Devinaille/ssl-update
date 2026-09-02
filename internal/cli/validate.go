package cli

import (
	"context"
	"log/slog"
	"time"

	"github.com/spf13/cobra"

	"ssl-update/internal/config"
	"ssl-update/internal/destination"
)

func newValidateCmd() *cobra.Command {
	var timeout time.Duration
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate config syntax and connectivity to all destinations",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfgPath, _ := cmd.Flags().GetString("config")
			return runValidate(cmd.Context(), cfgPath, timeout)
		},
	}
	cmd.Flags().DurationVar(&timeout, "timeout", 30*time.Second, "per-destination timeout")
	return cmd
}

func runValidate(ctx context.Context, cfgPath string, timeout time.Duration) error {
	cfg, err := config.LoadFile(cfgPath)
	if err != nil {
		return StartupError("config", err)
	}
	requiredBad := 0
	for _, d := range cfg.Destinations {
		dest, err := destination.Create(d.Type, d.Name, d.Config)
		if err != nil {
			slog.Error("[FAIL] destination create", "dest", d.Name, "type", d.Type, "err", err.Error())
			if d.Required {
				requiredBad++
			}
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, timeout)
		err = dest.Validate(cctx)
		cancel()
		if err != nil {
			slog.Error("[FAIL] validate", "dest", d.Name, "err", err.Error())
			if d.Required {
				requiredBad++
			}
			continue
		}
		slog.Info("[OK] validate", "dest", d.Name, "type", d.Type)
	}
	if requiredBad > 0 {
		return RuntimeError(1)
	}
	slog.Info("all destinations OK", "count", len(cfg.Destinations))
	return nil
}
