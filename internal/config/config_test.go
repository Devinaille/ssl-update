package config

import (
	"strings"
	"testing"
)

func TestLoad_ValidYAML(t *testing.T) {
	yaml := `
log:
  level: info
  format: text
  file: /tmp/ssl-update.log
concurrency: 3
destinations:
  - name: prod-safeline
    type: safeline
    required: true
    config:
      api_url: https://10.0.0.5:9443
      api_token: abc
`
	cfg, err := Load(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Concurrency != 3 {
		t.Errorf("Concurrency = %d, want 3", cfg.Concurrency)
	}
	if len(cfg.Destinations) != 1 {
		t.Fatalf("len(Destinations) = %d, want 1", len(cfg.Destinations))
	}
	d := cfg.Destinations[0]
	if d.Name != "prod-safeline" || d.Type != "safeline" || !d.Required {
		t.Errorf("destination = %+v", d)
	}
	if d.Config["api_url"] != "https://10.0.0.5:9443" {
		t.Errorf("config.api_url = %v", d.Config["api_url"])
	}
}

func TestLoad_Defaults(t *testing.T) {
	yaml := `destinations: []`
	cfg, err := Load(strings.NewReader(yaml))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Log.Level != "info" {
		t.Errorf("default Log.Level = %q, want info", cfg.Log.Level)
	}
	if cfg.Log.Format != "text" {
		t.Errorf("default Log.Format = %q, want text", cfg.Log.Format)
	}
	if cfg.Concurrency != 5 {
		t.Errorf("default Concurrency = %d, want 5", cfg.Concurrency)
	}
}

func TestValidate_RejectsMissingName(t *testing.T) {
	cfg := &RootConfig{
		Destinations: []DestinationConfig{
			{Name: "", Type: "safeline", Config: map[string]any{"api_url": "x"}},
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for empty name, got nil")
	}
}

func TestValidate_RejectsUnknownLogLevel(t *testing.T) {
	cfg := &RootConfig{Log: LogConfig{Level: "verbose"}}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for bad log level, got nil")
	}
}

func TestValidate_RejectsDuplicateDestinationName(t *testing.T) {
	cfg := &RootConfig{
		Destinations: []DestinationConfig{
			{Name: "dup", Type: "safeline"},
			{Name: "dup", Type: "aliyun_esa"},
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for duplicate name, got nil")
	}
}

func TestValidate_AcceptsValid(t *testing.T) {
	cfg := &RootConfig{
		Log:         LogConfig{Level: "debug", Format: "json"},
		Concurrency: 2,
		Destinations: []DestinationConfig{
			{Name: "a", Type: "safeline", Required: true},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}
}
