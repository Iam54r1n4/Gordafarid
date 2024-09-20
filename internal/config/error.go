package config

import "errors"

var (
	errInvalidConfigFile      = errors.New("invalid config file")
	errEmptyServerCredentials = errors.New("server.credentials is empty")
)
