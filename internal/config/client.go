// Package config provides configuration structures and functions for the Gordafarid client.
package config

import (
	"fmt"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/Iam54r1n4/Gordafarid/pkg/net/protocol/gordafarid/crypto"
)

// clientAddr holds the configuration for the client
type clientAddr struct {
	Address string `toml:"address"` // The address for the client to connect to
}

// socks5credentialsConfig is a map of usernames to passwords for SOCKS5 authentication
type socks5credentialsConfig map[string]string

// ClientConfig represents the complete configuration for a Gordafarid client
type ClientConfig struct {
	Server            serverAddr              `toml:"server"`            // Server configuration
	Client            clientAddr              `toml:"client"`            // Client configuration
	CryptoAlgorithm   string                  `toml:"cryptoAlgorithm"`   // Encryption algorithm to use
	Account           Account                 `toml:"account"`           // User account information
	Timeout           timeoutConfig           `toml:"timeout"`           // Timeout settings
	Socks5Credentials socks5credentialsConfig `toml:"socks5Credentials"` // SOCKS5 authentication credentials for client side
}

// loadClientConfig reads and parses the client configuration from a TOML file
// It returns a pointer to the ClientConfig and any error encountered
func loadClientConfig(path string) (*ClientConfig, error) {
	var config ClientConfig
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

// IsSocks5AuthEnabled checks if SOCKS5 authentication is enabled
// Returns true if there are any SOCKS5 credentials configured
func (cc *ClientConfig) IsSocks5AuthEnabled() bool {
	return len(cc.Socks5Credentials) > 0
}

// validate checks if all required fields in the ClientConfig are properly set
// It returns an error if any required field is missing or invalid
func (cc *ClientConfig) validate() error {
	var missingFields []string

	// Check for missing required fields
	if len(cc.Server.Address) < 1 {
		missingFields = append(missingFields, "server.address")
	}
	if len(cc.Client.Address) < 1 {
		missingFields = append(missingFields, "client.address")
	}
	if len(cc.CryptoAlgorithm) < 1 {
		missingFields = append(missingFields, "cryptoAlgorithm")
	}
	if len(cc.Account.Username) < 1 {
		missingFields = append(missingFields, "account.username")
	}
	if len(cc.Account.Password) < 1 {
		missingFields = append(missingFields, "account.password")
	}

	// If any required fields are missing, return an error
	if len(missingFields) > 0 {
		return fmt.Errorf("missing fields: %s", strings.Join(missingFields, ", "))
	}

	// Validate the crypto algorithm and password
	if err := crypto.IsCryptoSupported(cc.CryptoAlgorithm, cc.Account.Password); err != nil {
		return err
	}

	return nil
}

// applyDefaultValues sets default timeout values if they are not specified in the configuration
func (cc *ClientConfig) applyDefaultValues() {
	// Set default dial timeout to 10 seconds if not specified
	if cc.Timeout.DialTimeout == 0 {
		cc.Timeout.DialTimeout = 10
	}
	// Set default SOCKS5 handshake timeout to 10 seconds if not specified
	if cc.Timeout.Socks5HandshakeTimeout == 0 {
		cc.Timeout.Socks5HandshakeTimeout = 10
	}
	// Set default Gordafarid handshake timeout to 10 seconds if not specified
	if cc.Timeout.GordafaridHandshakeTimeout == 0 {
		cc.Timeout.GordafaridHandshakeTimeout = 10
	}
}
