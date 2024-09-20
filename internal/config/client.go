package config

import (
	"fmt"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/Iam54r1n4/Gordafarid/core/net/protocol/gordafarid/crypto"
)

// clientAddr holds the configuration for the client
type clientAddr struct {
	Address string `toml:"address"` // The address for the client to connect to
}

// socks5credentialsConfig is a map of usernames to passwords
type socks5credentialsConfig map[string]string

type ClientConfig struct {
	Server            serverAddr              `toml:"server"`
	Client            clientAddr              `toml:"client"`
	CryptoAlgorithm   string                  `toml:"cryptoAlgorithm"`
	Account           Account                 `toml:"account"`
	Timeout           timeoutConfig           `toml:"timeout"`
	Socks5Credentials socks5credentialsConfig `toml:"socks5Credentials"`
}

func loadClientConfig(path string) (*ClientConfig, error) {
	var config ClientConfig
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

func (cc *ClientConfig) IsSocks5AuthEnabled() bool {
	return len(cc.Socks5Credentials) > 0
}

func (cc *ClientConfig) validate() error {
	var missingFields []string

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
	if len(missingFields) > 0 {
		return fmt.Errorf("missing fields: %s", strings.Join(missingFields, ", "))
	}
	if err := crypto.IsCryptoSupported(cc.CryptoAlgorithm, cc.Account.Password); err != nil {
		return err
	}

	return nil
}

func (cc *ClientConfig) applyDefaultValues() {
	if cc.Timeout.DialTimeout == 0 {
		cc.Timeout.DialTimeout = 10
	}
	if cc.Timeout.Socks5HandshakeTimeout == 0 {
		cc.Timeout.Socks5HandshakeTimeout = 10
	}
	if cc.Timeout.GordafaridHandshakeTimeout == 0 {
		cc.Timeout.GordafaridHandshakeTimeout = 10
	}
}
