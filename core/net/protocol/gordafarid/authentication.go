package gordafarid

// handleAuthentication manages the authentication process for a Gordafarid connection.
// This method is responsible for verifying the client's credentials and setting up
// the account information if the authentication is successful.
func (c *Conn) handleAuthentication() error {
	// Extract the hash from the client's greeting message.
	// This hash is used as a unique identifier for the client.
	greetingHash := c.greeting.hash

	// Attempt to retrieve the password associated with the greeting hash
	// from the server's configuration. The server configuration contains
	// a map of valid greeting hashes to their corresponding passwords.
	password, exists := c.config.serverCredentials[greetingHash]

	// If the greeting hash doesn't exist in the server's credentials,
	// it means the client is not recognized or authorized.
	if !exists {
		// Return an authentication failure error.
		// This error should be handled by the caller to take appropriate action,
		// such as closing the connection or requesting re-authentication.
		return errGordafaridAuthFailed
	}

	// If the credentials are valid, create an account object for the authenticated client.
	// This account object stores the client's identifying information.
	c.account = account{
		hash:     greetingHash, // Store the unique identifier (hash) for this account
		password: password,     // Store the password associated with this account
	}

	// Return nil to indicate successful authentication.
	// The caller can proceed with further communication or setup for this authenticated connection.
	return nil
}
