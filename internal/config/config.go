package config

import (
	"fmt"
	"strings"

	"github.com/BurntSushi/toml"
)

const defaultConfigFilePath = "./config.toml"

type Mode int

const (
	ModeClient Mode = iota
	ModeServer
)

type Config struct {
	Client struct {
		Address string
	} `toml:"client"`
	Server struct {
		Address string
	} `toml:"server"`
	Crypto struct {
		Password string
	} `toml:"crypto"`

	DialTimeout      int `toml:"dialtimeout"`      // In seconds
	HandshakeTimeout int `toml:"handshaketimeout"` // In seconds
}

func LoadConfig(path string, mode Mode) (*Config, error) {
	if path == "" {
		path = defaultConfigFilePath
	}
	var config Config
	if _, err := toml.DecodeFile(path, &config); err != nil {
		return nil, err
	}
	if err := validateConfig(&config, &mode); err != nil {
		return nil, err
	}
	applyDefaultValues(&config)
	return &config, nil
}

func validateConfig(cfg *Config, mode *Mode) error {
	var missingFields []string
	if *mode == ModeClient {
		if cfg.Client.Address == "" {
			missingFields = append(missingFields, "client.address")
		}
	}

	if cfg.Server.Address == "" {
		missingFields = append(missingFields, "server.address")
	}
	if cfg.Crypto.Password == "" {
		missingFields = append(missingFields, "crypto.password")
	}
	if len(missingFields) > 0 {
		return fmt.Errorf("missing fields: %s", strings.Join(missingFields, ", "))
	}
	return nil
}
func applyDefaultValues(cfg *Config) {
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = 10
	}
	if cfg.HandshakeTimeout == 0 {
		cfg.HandshakeTimeout = 10
	}
}
