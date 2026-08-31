package state

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoad_MissingFile(t *testing.T) {
	s, err := Load(filepath.Join(t.TempDir(), "no-such.json"))
	if err != nil {
		t.Errorf("missing file should be non-error, got %v", err)
	}
	if s == nil {
		t.Fatal("state should not be nil even when file missing")
	}
	if len(s.Deployments) != 0 {
		t.Errorf("new state should have no deployments")
	}
}

func TestSaveAndLoad_Roundtrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, _ := Load(path)
	s.Set("prod-safeline:wildcard-a-com", Entry{
		DestName:            "prod-safeline",
		CertName:            "wildcard-a-com",
		CertID:              "3",
		LastDeployedAt:      time.Now().UTC().Truncate(time.Second),
		LastCertFingerprint: "sha256:abc",
	})
	if err := s.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}
	s2, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	e, ok := s2.Get("prod-safeline:wildcard-a-com")
	if !ok {
		t.Fatal("entry not found after roundtrip")
	}
	if e.CertID != "3" {
		t.Errorf("CertID = %q, want 3", e.CertID)
	}
	if e.LastCertFingerprint != "sha256:abc" {
		t.Errorf("LastCertFingerprint = %q", e.LastCertFingerprint)
	}
}

func TestGet_NotPresent(t *testing.T) {
	s, _ := Load(filepath.Join(t.TempDir(), "x.json"))
	if _, ok := s.Get("nope"); ok {
		t.Error("expected ok=false for missing key")
	}
}

func TestSet_Overwrites(t *testing.T) {
	s, _ := Load(filepath.Join(t.TempDir(), "x.json"))
	s.Set("k", Entry{CertID: "1"})
	s.Set("k", Entry{CertID: "2"})
	e, _ := s.Get("k")
	if e.CertID != "2" {
		t.Errorf("CertID = %q, want 2 (overwrite)", e.CertID)
	}
}

func TestLoad_CorruptJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte("{not json"), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := Load(path)
	if err == nil {
		t.Error("expected error for corrupt JSON")
	}
	if s == nil {
		t.Error("state should still be returned for recovery")
	}
	if len(s.Deployments) != 0 {
		t.Error("recovered state should be empty")
	}
}

func TestSave_AtomicRename(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, _ := Load(path)
	s.Set("k", Entry{CertID: "1"})
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(t.TempDir())
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".tmp" {
			t.Errorf("tmp file left behind: %s", e.Name())
		}
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("state file not created: %v", err)
	}
}
