package config

import (
	"fmt"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/Iam54r1n4/Gordafarid/core/crypto"
	"github.com/Iam54r1n4/Gordafarid/internal/proxy_error"
)

// DefaultConfigFilePath is the default path for the configuration file
const DefaultConfigFilePath = "./config.toml"

// Mode represents the operating mode of the application
type Mode int

const (
	// ModeClient represents the client mode
	ModeClient Mode = iota
	// ModeServer represents the server mode
	ModeServer
)

// cryptoConfig holds the configuration for cryptographic operations
type cryptoConfig struct {
	Algorithm string `toml:"algorithm"` // The cryptographic algorithm to use
	Password  string `toml:"password"`  // The password for the cryptographic operations
}

// clientConfig holds the configuration for the client
type clientConfig struct {
	Address string `toml:"address"` // The address for the client to connect to
}

// serverConfig holds the configuration for the server
type serverConfig struct {
	Address string `toml:"address"` // The address for the server to listen on
}

// timeoutConfig holds various timeout settings
type timeoutConfig struct {
	DialTimeout             int `toml:"dialTimeout"`             // Dial timeout in seconds
	Socks5HandshakeTimeout  int `toml:"socks5HandshakeTimeout"`  // SOCKS5 handshake timeout in seconds
	Socks5ValidationTimeout int `toml:"socks5ValidationTimeout"` // SOCKS5 validation timeout in milliseconds
}

// credentialsConfig is a map of usernames to passwords
type credentialsConfig map[string]string

// Config is the main configuration structure
type Config struct {
	Client      clientConfig      `toml:"client"`      // Client-specific configuration
	Server      serverConfig      `toml:"server"`      // Server-specific configuration
	Crypto      cryptoConfig      `toml:"crypto"`      // Cryptographic configuration
	Timeout     timeoutConfig     `toml:"timeout"`     // Timeout settings
	Credentials credentialsConfig `toml:"credentials"` // User credentials
}

// LoadConfig loads the configuration from a file and validates it
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

// validateConfig checks if the configuration is valid
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

// validateCryptoFields checks if the cryptographic configuration is valid
func validateCryptoFields(cfg *Config) error {
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

// applyDefaultValues sets default values for timeout settings if not specified
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
