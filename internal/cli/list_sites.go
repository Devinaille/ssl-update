package cli

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"ssl-update/internal/config"
	"ssl-update/internal/destination"
	"ssl-update/internal/destination/aliyun_esa"
)

// newListSitesCmd lists ESA sites for a configured aliyun_esa destination.
// This is the missing "how do I find my site_id?" tool — the API requires
// a numeric SiteId that has no human-readable counterpart in the console.
func newListSitesCmd() *cobra.Command {
	var name string
	cmd := &cobra.Command{
		Use:   "list-sites",
		Short: "List Aliyun ESA sites (discover site_id for an aliyun_esa destination)",
		Long: `List all ESA sites under the AccessKey configured for a given
aliyun_esa destination. Use this once to discover the numeric SiteId to
put in your config (the 1234567890123 placeholder in config.example.yaml
is not a real value).

Example:
  ssl-update list-sites --name prod-esa`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfgPath, _ := cmd.Flags().GetString("config")
			return runListSites(cmd.Context(), cfgPath, name)
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "destination name from config (must be type aliyun_esa)")
	_ = cmd.MarkFlagRequired("name")
	return cmd
}

func runListSites(ctx context.Context, cfgPath, name string) error {
	cfg, err := config.LoadFile(cfgPath)
	if err != nil {
		return StartupError("config", err)
	}

	var found *config.DestinationConfig
	for i := range cfg.Destinations {
		if cfg.Destinations[i].Name == name {
			d := cfg.Destinations[i]
			found = &d
			break
		}
	}
	if found == nil {
		return fmt.Errorf("destination %q not found in config", name)
	}
	if found.Type != "aliyun_esa" {
		return fmt.Errorf("destination %q is type %q; list-sites is only for aliyun_esa destinations", name, found.Type)
	}

	dest, err := destination.Create(found.Type, found.Name, found.Config)
	if err != nil {
		return StartupError("destination "+found.Name, err)
	}

	esa, ok := dest.(*aliyun_esa.AliyunESA)
	if !ok {
		// Defensive: if aliyun_esa's New() ever changes, this fails loud.
		return fmt.Errorf("destination %q did not construct to *aliyun_esa.AliyunESA (type=%s)", name, found.Type)
	}

	sites, err := esa.ListSites(ctx)
	if err != nil {
		return fmt.Errorf("list sites for %q: %w", name, err)
	}
	if len(sites) == 0 {
		fmt.Fprintf(os.Stderr, "(no sites found under %q — check your AccessKey has esa:ListSites permission)\n", name)
		return nil
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SITE_ID\tSITE_NAME\tSTATUS\tACCESS_TYPE\tCOVERAGE\tPLAN")
	for _, s := range sites {
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\n",
			s.SiteID, s.SiteName, s.Status, s.AccessType, s.Coverage, s.PlanName)
	}
	_ = tw.Flush()

	fmt.Fprintf(os.Stderr, "\n%d site(s) found. Copy the SITE_ID value into your config.yaml.\n", len(sites))
	return nil
}
