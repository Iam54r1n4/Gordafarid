// Package main is the entry point for the Gordafarid server application.
package main

import (
	"errors"

	"github.com/Iam54r1n4/Gordafarid/core/crypto"
	"github.com/Iam54r1n4/Gordafarid/core/server"
	"github.com/Iam54r1n4/Gordafarid/internal/config"
	"github.com/Iam54r1n4/Gordafarid/internal/logger"
	"github.com/Iam54r1n4/Gordafarid/internal/proxy_error"
)

// main is the entry point of the application.
// It loads configs, starts the server, and handles incoming connections.
func main() {
	// Load the configuration from the specified file
	cfg, err := config.LoadConfig("./config.toml", config.ModeServer)
	if err != nil {
		logger.Fatal(errors.Join(proxy_error.ErrInvalidConfigFile, err))
	}

	// Initialize the encryption algorithm
	aead, err := crypto.NewAEAD(cfg.Crypto.Algorithm, []byte(cfg.Crypto.Password))
	if err != nil {
		logger.Fatal(errors.Join(proxy_error.ErrCryptoInitFailed, err))
	}

	server := server.NewServer(cfg, aead)
	if err = server.Listen(); err != nil {
		logger.Fatal(errors.Join(proxy_error.ErrClientListenFailed, err))
	}

	server.Start()

}
