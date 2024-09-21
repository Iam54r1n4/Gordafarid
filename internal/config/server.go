// Package config provides configuration management for the Gordafarid server.
package config

import (
	"fmt"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/Iam54r1n4/Gordafarid/pkg/net/protocol/gordafarid/crypto"
)

// serverAddr holds the configuration for the server
type serverAddr struct {
	Address  string `toml:"address"`  // The address for the server to listen on
	HashSalt string `toml:"hashSalt"` // The hash salt for the Gordafarid
}

// ServerConfig represents the main configuration structure for the Gordafarid server.
type ServerConfig struct {
	Server          serverAddr    `toml:"server"`          // Server address configuration
	CryptoAlgorithm string        `toml:"cryptoAlgorithm"` // Cryptographic algorithm to be used
	Credentials     []Account     `toml:"credentials"`     // List of user accounts for the Gordafarid authentication
	Timeout         timeoutConfig `toml:"timeout"`         // Timeout settings
}

// loadServerConfig reads and parses the server configuration from a TOML file.
// It returns a pointer to ServerConfig and any error encountered during the process.
func loadServerConfig(path string) (*ServerConfig, error) {
	var config ServerConfig
	var err error

	// Decode the TOML file into the config struct
	if _, err = toml.DecodeFile(path, &config); err != nil {
		return nil, err
	}

	// Validate the configuration
	if err = config.validate(); err != nil {
		return nil, err
	}

	// Apply default values for any unspecified fields
	config.applyDefaultValues()

	return &config, nil
}

// validate checks the ServerConfig for any missing or invalid fields.
// It returns an error if any issues are found.
func (sc *ServerConfig) validate() error {
	var missingFields []string

	// Check for missing required fields
	if len(sc.Server.Address) < 1 {
		missingFields = append(missingFields, "server.address")
	}
	if len(sc.CryptoAlgorithm) < 1 {
		missingFields = append(missingFields, "cryptoAlgorithm")
	}

	// If any required fields are missing, return an error
	if len(missingFields) > 0 {
		return fmt.Errorf("missing fields: %s", strings.Join(missingFields, ", "))
	}

	// Validate the server credentials
	if len(sc.Credentials) < 1 {
		return errEmptyServerCredentials
	}
	// Validate each credential
	for i, cred := range sc.Credentials {
		if len(cred.Username) < 1 {
			return fmt.Errorf("element at index %d has empty username in credentials", i)
		}
		if len(cred.Password) < 1 {
			return fmt.Errorf("element at index %d has empty password in credentials", i)
		}

		// Check if the crypto algorithm is supported and the password meets the requirements
		if err := crypto.IsCryptoSupported(sc.CryptoAlgorithm, cred.Password); err != nil {
			keyLength, _ := crypto.GetAlgorithmKeySize(sc.CryptoAlgorithm)
			return fmt.Errorf("element at index %d has invalid password in credentials, the required length is %d", i, keyLength)
		}
	}
	return nil
}

// applyDefaultValues sets default timeout values if they are not specified in the configuration.
func (sc *ServerConfig) applyDefaultValues() {
	// Set default DialTimeout to 10 seconds if not specified
	if sc.Timeout.DialTimeout == 0 {
		sc.Timeout.DialTimeout = 10
	}

	// Set default Socks5HandshakeTimeout to 10 seconds if not specified
	if sc.Timeout.Socks5HandshakeTimeout == 0 {
		sc.Timeout.Socks5HandshakeTimeout = 10
	}

	// Set default GordafaridHandshakeTimeout to 10 seconds if not specified
	if sc.Timeout.GordafaridHandshakeTimeout == 0 {
		sc.Timeout.GordafaridHandshakeTimeout = 10
	}

	if len(sc.Server.HashSalt) < 1 {
		sc.Server.HashSalt = defaultHashSalt
	}
}
