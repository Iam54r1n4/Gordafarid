package flags

import (
	"flag"
)

// The program's flags
var (
	// CfgPathFlag is the path to the configuration file
	CfgPathFlag string

	// HashSaltFlag is the hash salt for Gordafarid authentication
	HashSaltFlag string
)

// Default values for the flags
const (
	// DefaultConfigFilePath is the default path for the configuration file
	defaultConfigFilePath = "./config.toml"
)

// init initializes the command-line flags
func init() {
	// Set up the configuration file path flag
	flag.StringVar(&CfgPathFlag, "config", defaultConfigFilePath, "path to config file")

	// Parse the command-line flags
	flag.Parse()
}
