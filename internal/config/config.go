// Package config provides configuration structures and functions for the Gordafarid project.
package config

import (
	"errors"
	"sync"

	"github.com/Iam54r1n4/Gordafarid/internal/logger"
)

// timeoutConfig holds various timeout settings for the application.
type timeoutConfig struct {
	DialTimeout                int `toml:"dialTimeout"`                // Dial timeout in seconds
	Socks5HandshakeTimeout     int `toml:"socks5HandshakeTimeout"`     // SOCKS5 handshake timeout in seconds
	GordafaridHandshakeTimeout int `toml:"gordafaridHandshakeTimeout"` // Gordafarid handshake timeout in seconds
}

// Account holds the account information for authentication.
type Account struct {
	Username string `toml:"username"` // Username for authentication
	Password string `toml:"password"` // Password for authentication
}

var (
	clientConfig            *ClientConfig // Holds the client configuration
	serverConfig            *ServerConfig // Holds the server configuration
	clientConfigLoadingOnce sync.Once     // Ensures client config is loaded only once
	serverConfigLoadingOnce sync.Once     // Ensures server config is loaded only once
)

// GetClientCofig loads and returns the client configuration.
// It uses sync.Once to ensure the configuration is loaded only once, even in concurrent scenarios.
// If there's an error loading the configuration, it logs a fatal error and terminates the program.
//
// Parameters:
//   - path: The file path to the client configuration file.
//
// Returns:
//   - *ClientConfig: A pointer to the loaded client configuration.
func GetClientCofig(path string) *ClientConfig {
	clientConfigLoadingOnce.Do(func() {
		var err error
		if clientConfig, err = loadClientConfig(path); err != nil {
			logger.Fatal(errors.Join(errInvalidConfigFile, err))
		}
	})
	return clientConfig
}

// GetServerConfig loads and returns the server configuration.
// It uses sync.Once to ensure the configuration is loaded only once, even in concurrent scenarios.
// If there's an error loading the configuration, it logs a fatal error and terminates the program.
//
// Parameters:
//   - path: The file path to the server configuration file.
//
// Returns:
//   - *ServerConfig: A pointer to the loaded server configuration.
func GetServerConfig(path string) *ServerConfig {
	serverConfigLoadingOnce.Do(func() {
		var err error
		if serverConfig, err = loadServerConfig(path); err != nil {
			logger.Fatal(errors.Join(errInvalidConfigFile, err))
		}
	})
	return serverConfig
}
