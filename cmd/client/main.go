// Package main is the entry point for the client application.
package main

import (
	"errors"

	"github.com/Iam54r1n4/Gordafarid/internal/client"
	"github.com/Iam54r1n4/Gordafarid/internal/config"
	"github.com/Iam54r1n4/Gordafarid/internal/flags" // Check its init function
	"github.com/Iam54r1n4/Gordafarid/internal/logger"
	"github.com/Iam54r1n4/Gordafarid/internal/shared_error"
)

// main is the entry point of the client application.
// It initializes the configuration, creates a new client,
// starts listening for incoming connections, and begins
// the client's main operation.
func main() {
	// Get the client configuration using the path specified in the flags.
	cfg := config.GetClientCofig(flags.CfgPathFlag)

	// Create a new client instance with the obtained configuration.
	client := client.NewClient(cfg)

	// Start listening for incoming socks5 connections.
	// If an error occurs during listening, log a fatal error and exit.
	if err := client.Listen(); err != nil {
		logger.Fatal(errors.Join(shared_error.ErrClientListenFailed, err))
	}

	// Begin the client's main operation.
	client.Start()
}
