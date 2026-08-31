package cli

import (
	"context"
	"fmt"
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
	bad := 0
	for _, d := range cfg.Destinations {
		dest, err := destination.Create(d.Type, d.Name, d.Config)
		if err != nil {
			fmt.Printf("[FAIL] %s (%s): %v\n", d.Name, d.Type, err)
			bad++
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, timeout)
		err = dest.Validate(cctx)
		cancel()
		if err != nil {
			fmt.Printf("[FAIL] %s: %v\n", d.Name, err)
			bad++
			continue
		}
		fmt.Printf("[OK]   %s (%s)\n", d.Name, d.Type)
	}
	if bad > 0 {
		return RuntimeError(1)
	}
	fmt.Printf("\n%d destination(s) OK\n", len(cfg.Destinations))
	return nil
}
