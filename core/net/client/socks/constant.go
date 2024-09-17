package socks

// Constants for SOCKS5 protocol
const (
	// socks5Version represents the SOCKS protocol version (SOCKS5)
	socks5Version = 5

	// Authentication methods
	noAuthMethod       = 0x00 // No authentication required
	userPassAuthMethod = 0x02 // Username/password authentication
	noAcceptableMethod = 0xFF // No acceptable method

	// User/Pass authentication constants
	userPassAuthVersion = 0x01 // Username/password authentication version
	userPassAuthSuccess = 0x00 // Authentication success
	userPassAuthFailed  = 0x01 // Authentication failed

	MaxInitialGreetingSize = 1 + 1 + 256 // Max size of initial greeting
)
