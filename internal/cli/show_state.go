package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"ssl-update/internal/config"
	"ssl-update/internal/state"
)

func newShowStateCmd() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "show-state",
		Short: "Print recorded deploys from state.json",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfgPath, _ := cmd.Flags().GetString("config")
			return runShowState(cfgPath, asJSON)
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print raw JSON instead of table")
	return cmd
}

func runShowState(cfgPath string, asJSON bool) error {
	cfg, err := config.LoadFile(cfgPath)
	if err != nil {
		return StartupError("config", err)
	}
	s, err := state.Load(expandHome(cfg.State.Path))
	if err != nil {
		return StartupError("state", err)
	}
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(s)
	}
	if len(s.Deployments) == 0 {
		fmt.Println("(no deployments recorded)")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "DEST\tCERT_NAME\tCERT_ID\tDEPLOYED_AT\tFINGERPRINT")
	keys := make([]string, 0, len(s.Deployments))
	for k := range s.Deployments {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		e := s.Deployments[k]
		// State stores UTC times; display them with explicit " UTC"
		// suffix so users in non-UTC zones don't mistake local-time
		// output for the actual timestamp (state.json is the source of
		// truth and is always UTC).
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s UTC\t%s\n",
			e.DestName, e.CertName, e.CertID,
			e.LastDeployedAt.UTC().Format("2006-01-02 15:04:05"),
			e.LastCertFingerprint)
	}
	return tw.Flush()
}
