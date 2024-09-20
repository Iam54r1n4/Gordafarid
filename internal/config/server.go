package config

import (
	"fmt"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/Iam54r1n4/Gordafarid/core/net/protocol/gordafarid/crypto"
)

// serverAddr holds the configuration for the server
type serverAddr struct {
	Address string `toml:"address"` // The address for the server to listen on
}

type ServerConfig struct {
	Server          serverAddr    `toml:"server"`
	CryptoAlgorithm string        `toml:"cryptoAlgorithm"`
	Credentials     []Account     `toml:"credentials"`
	Timeout         timeoutConfig `toml:"timeout"`
}

func loadServerConfig(path string) (*ServerConfig, error) {
	var config ServerConfig
	var err error

	if _, err = toml.DecodeFile(path, &config); err != nil {
		return nil, err
	}
	if err = config.validate(); err != nil {
		return nil, err
	}
	config.applyDefaultValues()

	return &config, nil
}

func (sc *ServerConfig) validate() error {
	var missingFields []string
	if len(sc.Server.Address) < 1 {
		missingFields = append(missingFields, "server.address")
	}
	if len(sc.CryptoAlgorithm) < 1 {
		missingFields = append(missingFields, "cryptoAlgorithm")
	}
	if len(sc.Credentials) < 1 {
		missingFields = append(missingFields, "credentials")
	}
	if len(missingFields) > 0 {
		return fmt.Errorf("missing fields: %s", strings.Join(missingFields, ", "))
	}

	for i, cred := range sc.Credentials {
		if len(cred.Username) < 1 {
			return fmt.Errorf("element at index %d has empty username in credentials", i)
		}
		if len(cred.Password) < 1 {
			return fmt.Errorf("element at index %d has empty password in credentials", i)
		}
		if err := crypto.IsCryptoSupported(sc.CryptoAlgorithm, cred.Password); err != nil {
			keyLength, _ := crypto.GetAlgorithmKeySize(sc.CryptoAlgorithm)
			return fmt.Errorf("element at index %d has invalid password in credentials, the required length is %d", i, keyLength)
		}
	}
	return nil
}

func (sc *ServerConfig) applyDefaultValues() {
	if sc.Timeout.DialTimeout == 0 {
		sc.Timeout.DialTimeout = 10
	}
	if sc.Timeout.Socks5HandshakeTimeout == 0 {
		sc.Timeout.Socks5HandshakeTimeout = 10
	}
	if sc.Timeout.GordafaridHandshakeTimeout == 0 {
		sc.Timeout.GordafaridHandshakeTimeout = 10
	}
}
