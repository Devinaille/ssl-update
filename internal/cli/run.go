package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"ssl-update/internal/cert"
	"ssl-update/internal/config"
	"ssl-update/internal/destination"
	"ssl-update/internal/runner"
	"ssl-update/internal/state"
)

func newRunCmd() *cobra.Command {
	var (
		only      []string
		dryRun    bool
		skipState bool
		timeout   time.Duration
	)
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Deploy cert to all configured destinations",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfgPath, _ := cmd.Flags().GetString("config")
			return runRun(cmd.Context(), cfgPath, runOpts{
				Only: only, DryRun: dryRun, SkipState: skipState, Timeout: timeout,
			})
		},
	}
	cmd.Flags().StringSliceVar(&only, "only", nil, "only deploy to named destination(s) (repeatable)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "print intended actions, do not actually deploy")
	cmd.Flags().BoolVar(&skipState, "skip-state", false, "do not read or write state.json")
	cmd.Flags().DurationVar(&timeout, "timeout", 5*time.Minute, "overall timeout")
	return cmd
}

type runOpts struct {
	Only      []string
	DryRun    bool
	SkipState bool
	Timeout   time.Duration
}

func runRun(ctx context.Context, cfgPath string, opts runOpts) error {
	cfg, err := config.LoadFile(cfgPath)
	if err != nil {
		return StartupError("config", err)
	}

	// Build destinations.
	var items []runner.NamedDest
	for _, d := range cfg.Destinations {
		if len(opts.Only) > 0 && !contains(opts.Only, d.Name) {
			continue
		}
		dest, err := destination.Create(d.Type, d.Name, d.Config)
		if err != nil {
			return StartupError("destination "+d.Name, err)
		}
		items = append(items, runner.NamedDest{Cfg: d, Dest: dest})
	}
	if len(items) == 0 {
		return StartupError("destinations", fmt.Errorf("no destinations matched (only=%v)", opts.Only))
	}

	// Read cert.
	certPath, keyPath, domain := resolveCertSource(cfg.Cert)
	bundle, err := cert.ReadBundle(certPath, keyPath, nil, domain)
	if err != nil {
		return StartupError("cert", err)
	}

	// Load state.
	var st *state.State
	if !opts.SkipState {
		st, err = state.Load(expandHome(cfg.State.Path))
		if err != nil {
			fmt.Fprintf(os.Stderr, "[WARN] state load failed (continuing fresh): %v\n", err)
		}
	}
	if st == nil {
		st, _ = state.Load("")
	}

	if opts.DryRun {
		for _, it := range items {
			fmt.Printf("[DRY-RUN] would deploy cert_name=%s to %s (%s)\n",
				cert.SanitizeName(bundle.MainDomain), it.Cfg.Name, it.Cfg.Type)
		}
		return nil
	}

	r := runner.New(items, st, cfg.Concurrency)
	code := r.Run(ctx, bundle)
	if err := st.Save(); err != nil {
		fmt.Fprintf(os.Stderr, "[WARN] state save failed: %v\n", err)
	}
	if code != 0 {
		return RuntimeError(code)
	}
	return nil
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

func resolveCertSource(c config.CertConfig) (certPath, keyPath, domain string) {
	if c.CertPath != "" {
		certPath = c.CertPath
	} else {
		certPath = os.Getenv("LE_CERT_PATH")
	}
	if c.KeyPath != "" {
		keyPath = c.KeyPath
	} else {
		keyPath = os.Getenv("LE_KEY_PATH")
	}
	if c.Domain != "" {
		domain = c.Domain
	} else {
		domain = os.Getenv("Le_DomainMain")
	}
	return
}

func expandHome(p string) string {
	if strings.HasPrefix(p, "~/") {
		if h, err := os.UserHomeDir(); err == nil {
			return h + p[1:]
		}
	}
	return p
}
