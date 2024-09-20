package flags

import (
	"flag"
)

// The program's flags
var (
	CfgPathFlag  string
	HashSaltFlag string
)

// Default values for the flags
const (
	// DefaultConfigFilePath is the default path for the configuration file
	defaultConfigFilePath = "./config.toml"

	// Hash salt for the Gordafarid authentication
	defaultHashSalt = "ZZA"
)

func init() {
	flag.StringVar(&CfgPathFlag, "config", defaultConfigFilePath, "path to config file")
	flag.StringVar(&HashSaltFlag, "hashSalt", defaultHashSalt, "hash salt for Gordafarid authentication")
	flag.Parse()
}
