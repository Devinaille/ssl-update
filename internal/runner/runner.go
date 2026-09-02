// Package runner orchestrates the parallel dispatch of a cert to all
// configured destinations and aggregates results into an exit code.
package runner

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"ssl-update/internal/cert"
	"ssl-update/internal/config"
	"ssl-update/internal/destination"
	"ssl-update/internal/state"
)

// NamedDest pairs a Destination with its config (used for name + required flag).
type NamedDest struct {
	Cfg  config.DestinationConfig
	Dest destination.Destination
}

type Runner struct {
	items       []NamedDest
	state       *state.State
	maxParallel int
}

func New(items []NamedDest, st *state.State, maxParallel int) *Runner {
	if maxParallel <= 0 {
		maxParallel = 5
	}
	return &Runner{items: items, state: st, maxParallel: maxParallel}
}

// Run dispatches the cert to all destinations in parallel and returns
// the exit code per spec §9.1:
//
//	0 = success (all required succeeded, optional may have failed)
//	1 = at least one required destination failed
//	2 = caller error (not produced by Run; reserved for startup)
func (r *Runner) Run(ctx context.Context, bundle cert.CertBundle) int {
	sem := make(chan struct{}, r.maxParallel)
	required := requiredMap(r.items)
	var wg sync.WaitGroup
	results := make(chan result, len(r.items))

	for _, item := range r.items {
		// Pre-cancelled ctx: don't spawn the goroutine at all. Inside
		// the goroutine, the select below also checks ctx, but Go's
		// select is non-deterministic when both cases are ready — a
		// top-of-loop check is the only way to deterministically
		// guarantee no goroutine ever enters Deploy when ctx is
		// already done.
		if ctx.Err() != nil {
			break
		}
		item := item
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Acquire the concurrency slot inside the goroutine, racing
			// against ctx cancel. If ctx is already cancelled, this
			// goroutine never enters Deploy at all — much cleaner than
			// blocking the main loop on sem <- struct{}{}.
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				results <- result{
					name: item.Cfg.Name,
					err:  ctx.Err(),
				}
				return
			}
			start := time.Now()
			certName := item.Dest.CertName(bundle)
			hint := r.hintFor(item.Cfg.Name, certName)
			res, err := item.Dest.Deploy(ctx, bundle, hint)
			dur := time.Since(start)
			results <- result{
				name:     item.Cfg.Name,
				success:  err == nil,
				err:      err,
				duration: dur,
			}
			if err == nil {
				key := item.Cfg.Name + ":" + res.CertName
				r.state.Set(key, state.Entry{
					DestName:            item.Cfg.Name,
					CertName:            res.CertName,
					CertID:              res.CertID,
					LastDeployedAt:      res.DeployedAt,
					LastCertFingerprint: res.Fingerprint,
				})
			}
		}()
	}
	wg.Wait()
	close(results)

	var requiredFailed bool
	for res := range results {
		if res.err != nil {
			if required[res.name] {
				requiredFailed = true
				slog.Error("[ERROR] deploy failed", "dest", res.name, "err", res.err.Error())
			} else {
				slog.Warn("[WARN] deploy failed (optional)", "dest", res.name, "err", res.err.Error())
			}
		} else {
			slog.Info("[INFO] deployed", "dest", res.name, "duration", res.duration.String())
		}
	}
	if requiredFailed {
		return 1
	}
	return 0
}

func (r *Runner) hintFor(destName, certName string) string {
	if certName == "" {
		return ""
	}
	e, ok := r.state.Get(destName + ":" + certName)
	if !ok {
		return ""
	}
	return e.CertID
}

// requiredMap builds an O(1) lookup of which destinations are required.
// Pre-computed once before the result loop instead of doing an O(n)
// linear scan per result (was O(n^2) for n destinations).
func requiredMap(items []NamedDest) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, it := range items {
		m[it.Cfg.Name] = it.Cfg.Required
	}
	return m
}

type result struct {
	name     string
	success  bool
	err      error
	duration time.Duration
}
