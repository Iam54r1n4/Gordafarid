package config

import "errors"

var (
	errInvalidConfigFile      = errors.New("invalid config file")
	errCryptoAlgorithmEmpty   = errors.New("crypto.algorithm is empty")
	errCryptoInitFailed       = errors.New("the crypto initialization failed")
	errEmptyServerCredentials = errors.New("server.credentials is empty")
)
