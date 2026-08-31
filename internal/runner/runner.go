// Package runner orchestrates the parallel dispatch of a cert to all
// configured destinations and aggregates results into an exit code.
package runner

import (
	"context"
	"fmt"
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
	var wg sync.WaitGroup
	results := make(chan result, len(r.items))

	for _, item := range r.items {
		item := item
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
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
			if isRequired(r.items, res.name) {
				requiredFailed = true
				fmt.Printf("[ERROR] [%s] deploy failed: %v\n", res.name, res.err)
			} else {
				fmt.Printf("[WARN]  [%s] deploy failed (optional): %v\n", res.name, res.err)
			}
		} else {
			fmt.Printf("[INFO]  [%s] deployed in %s\n", res.name, res.duration)
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

func isRequired(items []NamedDest, name string) bool {
	for _, it := range items {
		if it.Cfg.Name == name {
			return it.Cfg.Required
		}
	}
	return false
}

type result struct {
	name     string
	success  bool
	err      error
	duration time.Duration
}
