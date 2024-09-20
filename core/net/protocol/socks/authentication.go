package socks

import (
	"context"
	"errors"
	"fmt"

	"github.com/Iam54r1n4/Gordafarid/core/net/utils"
)

// authenticate checks if the provided username and password are valid
// It returns nil if authentication is successful, or an error if it fails
func (c *Conn) authenticate() error {
	// If no credentials are set, authentication is not required
	if c.serverConfig.credentials == nil {
		return nil
	}

	// Check if the username exists in the credentials map
	password, ok := c.serverConfig.credentials[string(c.userPassAuth.username)]
	if !ok {
		return errSocks5AuthIncorrectUsername
	}

	// Compare the provided password with the stored password
	if string(c.userPassAuth.password) == password {
		return nil
	}

	return errSocks5AuthIncorrectPassword
}

// selectPreferredSocks5AuthMethod determines the best authentication method
// based on the methods provided by the client and the server's configuration
func (c *Conn) selectPreferredSocks5AuthMethod() (byte, error) {
	noAuth, userPassAuth := false, false

	// Iterate through the client's supported methods
	for _, method := range c.greeting.methods {
		if noAuth && userPassAuth {
			break
		}
		if method == noAuthMethod {
			noAuth = true
		} else if method == userPassAuthMethod {
			userPassAuth = true
		}
	}

	// Prefer username/password authentication if available
	if userPassAuth {
		return userPassAuthMethod, nil
	}

	// Fall back to no authentication if supported
	if noAuth {
		return noAuthMethod, nil
	}

	// If no acceptable method is found, return an error
	return noAcceptableMethod, errors.Join(errSocks5InvalidMethod, fmt.Errorf("sent auth methods: %v", c.greeting.methods))
}

// serverParseUserPassAuthMethodHeaders reads and parses the username/password
// authentication headers from the client
func (c *Conn) serverParseUserPassAuthMethodHeaders(ctx context.Context) error {
	// Read authentication version
	buf := make([]byte, 1)
	if _, err := utils.ReadWithContext(ctx, c.Conn, buf); err != nil {
		return errors.Join(errSocks5UnableToReadUserPassAuthVersion, err)
	}
	if buf[0] != userPassAuthVersion {
		return errors.Join(errSocks5UnsupportedUserPassAuthVersion, fmt.Errorf("sent version: %d", buf[0]))
	}
	c.userPassAuth.version = buf[0]

	// Read username length and username
	if _, err := utils.ReadWithContext(ctx, c.Conn, buf); err != nil {
		return errors.Join(errSocks5UnableToReadUserPassAuthUsernameLength, err)
	}
	c.userPassAuth.uLen = buf[0]
	c.userPassAuth.username = make([]byte, c.userPassAuth.uLen)
	if _, err := utils.ReadWithContext(ctx, c.Conn, c.userPassAuth.username); err != nil {
		return errors.Join(errSocks5UnableToReadUserPassAuthUsername, err)
	}

	// Read password length and password
	if _, err := utils.ReadWithContext(ctx, c.Conn, buf); err != nil {
		return errors.Join(errSocks5UnableToReadUserPassAuthPasswordLength, err)
	}
	c.userPassAuth.pLen = buf[0]
	c.userPassAuth.password = make([]byte, c.userPassAuth.pLen)
	if _, err := utils.ReadWithContext(ctx, c.Conn, c.userPassAuth.password); err != nil {
		return errors.Join(errSocks5UnableToReadUserPassAuthPassword, err)
	}
	return nil
}

// serverHandleUserPassAuthMethodNegotiation handles the username/password
// authentication negotiation process
func (c *Conn) serverHandleUserPassAuthMethodNegotiation(ctx context.Context) error {
	var err error

	// Parse the authentication headers
	if err = c.serverParseUserPassAuthMethodHeaders(ctx); err != nil {
		return err
	}

	// Attempt to authenticate
	if err = c.authenticate(); err != nil {
		// Send failed response if auth failed
		if err := c.serverSendTwoBytesResponse(ctx, userPassAuthVersion, userPassAuthFailed); err != nil {
			return errors.Join(errSocks5UnableToSendUserPassAuthFailedResponse, err)
		}
		return errors.Join(errSocks5AuthenticationFailed, fmt.Errorf("username: %s, password: %s", string(c.userPassAuth.username), string(c.userPassAuth.password)))
	}

	// Send success response
	if err = c.serverSendTwoBytesResponse(ctx, userPassAuthVersion, userPassAuthSuccess); err != nil {
		return errors.Join(errSocks5UnableToSendUserPassAuthSuccessResponse, err)
	}

	return nil
}

// verifyMethods checks if the selected authentication method is compatible
// with the server's configuration
func (c *Conn) verifyMethods(bestMethod byte) error {
	// If username/password authentication is required and not supported, return an error
	if c.serverConfig.credentials != nil && bestMethod != userPassAuthMethod {
		return errors.Join(errSocks5NoAcceptableMethod, fmt.Errorf("sent nmethods: %d", c.greeting.nMethods))
	}
	return nil
}
