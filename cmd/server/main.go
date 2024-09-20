// Package main is the entry point for the Gordafarid server application.
package main

import (
	"errors"

	"github.com/Iam54r1n4/Gordafarid/internal/config"
	"github.com/Iam54r1n4/Gordafarid/internal/flags" // Check its init function
	"github.com/Iam54r1n4/Gordafarid/internal/logger"
	"github.com/Iam54r1n4/Gordafarid/internal/server"
	"github.com/Iam54r1n4/Gordafarid/internal/shared_error"
)

// main is the entry point of the application.
// It loads configs(config package init function), starts the server, and handles incoming connections.
func main() {

	cfg := config.GetServerConfig(flags.CfgPathFlag)

	server := server.NewServer(cfg)

	if err := server.Listen(); err != nil {
		logger.Fatal(errors.Join(shared_error.ErrClientListenFailed, err))
	}

	server.Start()
}
