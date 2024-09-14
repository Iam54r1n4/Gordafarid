// Package main is the entry point for the client application.
package main

import (
	"errors"

	"github.com/Iam54r1n4/Gordafarid/core/client"
	"github.com/Iam54r1n4/Gordafarid/core/crypto"
	"github.com/Iam54r1n4/Gordafarid/internal/config"
	"github.com/Iam54r1n4/Gordafarid/internal/logger"
	"github.com/Iam54r1n4/Gordafarid/internal/proxy_error"
)

// main is the entry point of the application.
// It loads configs, starts the client, and handles incoming connections.
func main() {
	// Load the config file
	cfg, err := config.LoadConfig("./config.toml", config.ModeClient)
	if err != nil {
		logger.Fatal(errors.Join(proxy_error.ErrInvalidConfigFile, err))
	}

	// Initialize encryption algorithm
	aead, err := crypto.NewAEAD(cfg.Crypto.Algorithm, []byte(cfg.Crypto.Password))
	if err != nil {
		logger.Fatal(errors.Join(proxy_error.ErrCryptoInitFailed, err))
	}

	client := client.NewClient(cfg, aead)
	if err = client.Listen(); err != nil {
		logger.Fatal(errors.Join(proxy_error.ErrClientListenFailed, err))
	}

	client.Start()
}
