package config

// DefaultConfigFilePath is the default path for the configuration file
const DefaultConfigFilePath = "./config.toml"

// timeoutConfig holds various timeout settings
type timeoutConfig struct {
	DialTimeout                int `toml:"dialTimeout"`                // Dial timeout in seconds
	Socks5HandshakeTimeout     int `toml:"socks5HandshakeTimeout"`     // SOCKS5 handshake timeout in seconds
	GordafaridHandshakeTimeout int `toml:"gordafaridHandshakeTimeout"` // Gordafarid handshake timeout in seconds
}

// Account holds the account information
type Account struct {
	Username string `toml:"username"`
	Password string `toml:"password"`
	Hash     string
}
