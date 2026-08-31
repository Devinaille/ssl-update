package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"ssl-update/internal/destination"
)

// NewRootCmd builds the root command and attaches all subcommands.
func NewRootCmd() *cobra.Command {
	var cfgPath string

	root := &cobra.Command{
		Use:           "ssl-update",
		Short:         "Push acme.sh-renewed certs to Safeline WAF and Aliyun ESA",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVarP(&cfgPath, "config", "c", "/etc/ssl-update/config.yaml", "config file path")
	root.AddCommand(newVersionCmd())

	// Other subcommands (newRunCmd / newValidateCmd / newShowStateCmd) are
	// registered in Tasks 9, 10, 11 to keep this task small and compilable.

	// Make cfgPath available to subcommands via context if needed later.
	_ = cfgPath
	return root
}

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
