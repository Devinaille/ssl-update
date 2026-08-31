// Package config loads and validates the YAML config file.
package config

import (
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

type RootConfig struct {
	Cert         CertConfig          `yaml:"cert"`
	State        StateConfig         `yaml:"state"`
	Log          LogConfig           `yaml:"log"`
	Concurrency  int                 `yaml:"concurrency"`
	Destinations []DestinationConfig `yaml:"destinations"`
}

type CertConfig struct {
	CertPath string `yaml:"cert_path"`
	KeyPath  string `yaml:"key_path"`
	Domain   string `yaml:"domain"`
}

type StateConfig struct {
	Path string `yaml:"path"`
}

type LogConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
	File   string `yaml:"file"`
}

type DestinationConfig struct {
	Name     string         `yaml:"name"`
	Type     string         `yaml:"type"`
	Required bool           `yaml:"required"`
	Config   map[string]any `yaml:"config"`
}

func Load(r io.Reader) (*RootConfig, error) {
	var cfg RootConfig
	dec := yaml.NewDecoder(r)
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func LoadFile(path string) (*RootConfig, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config %s: %w", path, err)
	}
	defer f.Close()
	return Load(f)
}

func (c *RootConfig) applyDefaults() {
	if c.Log.Level == "" {
		c.Log.Level = "info"
	}
	if c.Log.Format == "" {
		c.Log.Format = "text"
	}
	if c.Concurrency == 0 {
		c.Concurrency = 5
	}
	if c.State.Path == "" {
		c.State.Path = "~/.local/share/ssl-update/state.json"
	}
}

func (c *RootConfig) Validate() error {
	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("log.level %q invalid (want debug|info|warn|error)", c.Log.Level)
	}
	switch c.Log.Format {
	case "text", "json":
	default:
		return fmt.Errorf("log.format %q invalid (want text|json)", c.Log.Format)
	}
	seen := map[string]bool{}
	for i, d := range c.Destinations {
		if d.Name == "" {
			return fmt.Errorf("destinations[%d]: name required", i)
		}
		if d.Type == "" {
			return fmt.Errorf("destinations[%d] (%s): type required", i, d.Name)
		}
		if seen[d.Name] {
			return fmt.Errorf("destinations[%d] (%s): duplicate name", i, d.Name)
		}
		seen[d.Name] = true
	}
	return nil
}
