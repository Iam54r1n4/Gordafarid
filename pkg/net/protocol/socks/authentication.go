// Package socks implements the SOCKS5 proxy protocol.
package socks

import (
	"context"
	"errors"
	"fmt"

	"github.com/Iam54r1n4/Gordafarid/pkg/net/utils"
)

// authenticate checks if the provided username and password are valid.
// It returns nil if authentication is successful, or an error if it fails.
func (c *Conn) authenticate() error {
	// If no credentials are set, authentication is not required
	if c.serverConfig.credentials == nil {
		return nil
	}

	// Check if the username exists in the credentials map
	password, ok := c.serverConfig.credentials[string(c.userPassAuth.username)]
	if !ok {
		return errAuthIncorrectUsername
	}

	// Compare the provided password with the stored password
	if string(c.userPassAuth.password) == password {
		return nil
	}

	return errAuthIncorrectPassword
}

// selectPreferredSocks5AuthMethod determines the best authentication method
// based on the methods provided by the client and the server's configuration.
// It returns the selected method as a byte and an error if no acceptable method is found.
func (c *Conn) selectPreferredSocks5AuthMethod() (byte, error) {
	noAuth, userPassAuth := false, false

	// Iterate through the client's supported methods
	for _, method := range c.greeting.methods {

		if method == noAuthMethod {
			noAuth = true
		} else if method == userPassAuthMethod {
			userPassAuth = true
		}
		if noAuth && userPassAuth {
			break
		}
	}

	// Prefer username/password authentication if available and required
	if c.serverConfig.credentials != nil && userPassAuth {
		return userPassAuthMethod, nil
	}

	// Fall back to no authentication if supported and no credentials are required
	if c.serverConfig.credentials == nil && noAuth {
		return noAuthMethod, nil
	}

	// If no acceptable method is found, return an error
	return noAcceptableMethod, errors.Join(errInvalidMethod, fmt.Errorf("sent auth methods: %v", c.greeting.methods))
}

// serverParseUserPassAuthMethodHeaders reads and parses the username/password
// authentication headers from the client.
// It returns an error if there's any issue reading or parsing the headers.
func (c *Conn) serverParseUserPassAuthMethodHeaders(ctx context.Context) error {
	// Read authentication version
	buf := make([]byte, 1)
	if _, err := utils.ReadWithContext(ctx, c.Conn, buf); err != nil {
		return errors.Join(errUnableToReadUserPassAuthVersion, err)
	}
	if buf[0] != userPassAuthVersion {
		return errors.Join(errUnsupportedUserPassAuthVersion, fmt.Errorf("sent version: %d", buf[0]))
	}
	c.userPassAuth.version = buf[0]

	// Read username length and username
	if _, err := utils.ReadWithContext(ctx, c.Conn, buf); err != nil {
		return errors.Join(errUnableToReadUserPassAuthUsernameLength, err)
	}
	c.userPassAuth.uLen = buf[0]
	c.userPassAuth.username = make([]byte, c.userPassAuth.uLen)
	if _, err := utils.ReadWithContext(ctx, c.Conn, c.userPassAuth.username); err != nil {
		return errors.Join(errUnableToReadUserPassAuthUsername, err)
	}

	// Read password length and password
	if _, err := utils.ReadWithContext(ctx, c.Conn, buf); err != nil {
		return errors.Join(errUnableToReadUserPassAuthPasswordLength, err)
	}
	c.userPassAuth.pLen = buf[0]
	c.userPassAuth.password = make([]byte, c.userPassAuth.pLen)
	if _, err := utils.ReadWithContext(ctx, c.Conn, c.userPassAuth.password); err != nil {
		return errors.Join(errUnableToReadUserPassAuthPassword, err)
	}
	return nil
}

// serverHandleUserPassAuthMethodNegotiation handles the username/password
// authentication negotiation process.
// It parses the authentication headers, attempts to authenticate, and sends the appropriate response.
// Returns an error if any step in the process fails.
func (c *Conn) serverHandleUserPassAuthMethodNegotiation(ctx context.Context) error {

	// Parse the authentication headers
	if err := c.serverParseUserPassAuthMethodHeaders(ctx); err != nil {
		return err
	}

	// Attempt to authenticate
	if err := c.authenticate(); err != nil {
		// Send failed response if auth failed
		if sendErr := c.serverSendTwoBytesResponse(ctx, userPassAuthVersion, userPassAuthFailed); sendErr != nil {
			return errors.Join(errUnableToSendUserPassAuthFailedResponse, sendErr, err)
		}
		return errors.Join(errAuthenticationFailed, fmt.Errorf("username: %s", string(c.userPassAuth.username)))
	}

	// Send success response
	if err := c.serverSendTwoBytesResponse(ctx, userPassAuthVersion, userPassAuthSuccess); err != nil {
		return errors.Join(errUnableToSendUserPassAuthSuccessResponse, err)
	}

	return nil
}

// verifyMethods checks if the selected authentication method is compatible
// with the server's configuration.
// Returns an error if username/password authentication is required but not supported.
func (c *Conn) verifyMethods(bestMethod byte) error {
	// If username/password authentication is required and not supported, return an error
	if c.serverConfig.credentials != nil && bestMethod != userPassAuthMethod {
		return errors.Join(errNoAcceptableMethod, fmt.Errorf("sent nmethods: %d", c.greeting.nMethods))
	}
	return nil
}
