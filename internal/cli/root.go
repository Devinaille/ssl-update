package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"ssl-update/internal/config"
	"ssl-update/internal/destination"
)

// NewRootCmd builds the root command and attaches all subcommands.
func NewRootCmd() *cobra.Command {
	var (
		cfgPath   string
		logLevel  string
		logFormat string
	)

	root := &cobra.Command{
		Use:           "ssl-update",
		Short:         "Push acme.sh-renewed certs to Safeline WAF and Aliyun ESA",
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if cmd.Name() == "version" || cmd.Name() == "help" || cmd.Name() == "completion" {
				return nil
			}
			cfg, err := config.LoadFile(cfgPath)
			if err != nil {
				// Wrap so main.go can map this to exit code 2 (startup
				// error) instead of the default 1.
				return StartupError("config", err)
			}
			_, closer, err := setupLogger(cfg.Log, logLevel, logFormat)
			if err != nil {
				return StartupError("logger", err)
			}
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			cmd.SetContext(context.WithValue(ctx, closerKey{}, closer))
			return nil
		},
		PersistentPostRunE: func(cmd *cobra.Command, args []string) error {
			if c, ok := cmd.Context().Value(closerKey{}).(io.Closer); ok && c != nil {
				c.Close()
			}
			return nil
		},
	}
	root.PersistentFlags().StringVarP(&cfgPath, "config", "c", "/etc/ssl-update/config.yaml", "config file path")
	root.PersistentFlags().StringVar(&logLevel, "log-level", "", "override log level (debug|info|warn|error)")
	root.PersistentFlags().StringVar(&logFormat, "log-format", "", "override log format (text|json)")

	root.AddCommand(newVersionCmd())
	root.AddCommand(newRunCmd())
	root.AddCommand(newValidateCmd())
	root.AddCommand(newShowStateCmd())
	root.AddCommand(newListSitesCmd())
	return root
}

type closerKey struct{}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version and built-in destination types",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("ssl-update %s\n", Version)
			fmt.Printf("destination types: %v\n", destination.ListTypes())
		},
	}
}
