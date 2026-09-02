// Package state manages the JSON file that records last-deployed cert IDs
// per (destination, cert_name) pair.
package state

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const currentVersion = 1

// State is the in-memory representation of state.json.
type State struct {
	mu          sync.Mutex
	path        string
	dirty       bool
	Version     int              `json:"version"`
	Deployments map[string]Entry `json:"deployments"`
}

// Entry is one record of a previous successful deploy.
type Entry struct {
	DestName            string    `json:"dest_name"`
	CertName            string    `json:"cert_name"`
	CertID              string    `json:"cert_id"`
	LastDeployedAt      time.Time `json:"last_deployed_at"`
	LastCertFingerprint string    `json:"last_cert_fingerprint"`
}

// Load reads state from path. A missing file is non-fatal and returns an
// empty state. A corrupt file returns an error but also an empty state,
// so the caller can continue with no prior knowledge.
func Load(path string) (*State, error) {
	s := &State{
		path:        path,
		Version:     currentVersion,
		Deployments: map[string]Entry{},
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return s, fmt.Errorf("read state %s: %w", path, err)
	}
	if err := json.Unmarshal(data, s); err != nil {
		return s, fmt.Errorf("parse state %s: %w", path, err)
	}
	if s.Deployments == nil {
		s.Deployments = map[string]Entry{}
	}
	return s, nil
}

// Path returns the on-disk location of this state file.
func (s *State) Path() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.path
}

// Get returns the entry for a key (e.g., "prod-safeline:wildcard-a-com").
func (s *State) Get(key string) (Entry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.Deployments[key]
	return e, ok
}

// Set upserts an entry and marks the state dirty (will be written on next Save).
func (s *State) Set(key string, e Entry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Deployments[key] = e
	s.dirty = true
}

// Save atomically writes the state to disk. Safe to call even if not dirty.
// A state with no backing path (constructed via Load("")) is a no-op:
// prevents accidental tmp-file creation in the current working directory
// when the caller passed --skip-state.
func (s *State) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.dirty {
		return nil
	}
	if s.path == "" {
		return nil
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("mkdir state dir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, "state-*.json.tmp")
	if err != nil {
		return fmt.Errorf("create tmp: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("write tmp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("close tmp: %w", err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("rename: %w", err)
	}
	s.dirty = false
	return nil
}
