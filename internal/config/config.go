package config

import (
	"fmt"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/Iam54r1n4/Gordafarid/core/crypto"
	"github.com/Iam54r1n4/Gordafarid/internal/proxy_error"
)

const DefaultConfigFilePath = "./config.toml"

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
		Algorithm string
		Password  string
	} `toml:"crypto"`

	Timeout struct {
		DialTimeout             int `toml:"dialTimeout"`             // In seconds
		Socks5HandshakeTimeout  int `toml:"socks5HandshakeTimeout"`  // In seconds
		Socks5ValidationTimeout int `toml:"socks5ValidationTimeout"` // In millliseconds
	} `toml:"timeout"`
}

func LoadConfig(path string, mode Mode) (*Config, error) {
	if path == "" {
		path = DefaultConfigFilePath
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
	if len(missingFields) > 0 {
		return fmt.Errorf("missing fields: %s", strings.Join(missingFields, ", "))
	}

	return validateCryptoFields(cfg)

}
func validateCryptoFields(cfg *Config) error {
	// Check
	if cfg.Crypto.Algorithm == "" {
		return proxy_error.ErrCryptoAlgorithmEmpty
	}
	if cfg.Crypto.Password == "" {
		return proxy_error.ErrCryptoPasswordEmpty
	}
	if err := crypto.IsCryptoSupported(cfg.Crypto.Algorithm, cfg.Crypto.Password); err != nil {
		return err
	}
	return nil
}
func applyDefaultValues(cfg *Config) {
	if cfg.Timeout.DialTimeout == 0 {
		cfg.Timeout.DialTimeout = 10
	}
	if cfg.Timeout.Socks5HandshakeTimeout == 0 {
		cfg.Timeout.Socks5HandshakeTimeout = 10
	}
	if cfg.Timeout.Socks5ValidationTimeout == 0 {
		cfg.Timeout.Socks5ValidationTimeout = 500
	}
}
