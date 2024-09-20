package config

import (
	"errors"
	"sync"

	"github.com/Iam54r1n4/Gordafarid/internal/logger"
)

// timeoutConfig holds various timeout settings
type timeoutConfig struct {
	DialTimeout                int `toml:"dialTimeout"`                // Dial timeout in seconds
	Socks5HandshakeTimeout     int `toml:"socks5HandshakeTimeout"`     // SOCKS5 handshake timeout in seconds
	GordafaridHandshakeTimeout int `toml:"gordafaridHandshakeTimeout"` // Gordafarid handshake timeout in seconds
}

// Account holds the account information
type Account struct {
	Username string `toml:"username"`
	Password string `toml:"password"`
}

var (
	clientConfig            *ClientConfig
	serverConfig            *ServerConfig
	clientConfigLoadingOnce sync.Once
	serverConfigLoadingOnce sync.Once
)

func GetClientCofig(path string) *ClientConfig {
	clientConfigLoadingOnce.Do(func() {
		var err error
		if clientConfig, err = loadClientConfig(path); err != nil {
			logger.Fatal(errors.Join(err))
		}
	})
	return clientConfig
}
func GetServerConfig(path string) *ServerConfig {
	serverConfigLoadingOnce.Do(func() {
		var err error
		if serverConfig, err = loadServerConfig(path); err != nil {
			logger.Fatal(errors.Join(err))
		}
	})
	return serverConfig
}
