package socks

import (
	"errors"
	"fmt"

	"github.com/Iam54r1n4/Gordafarid/core/net/utils"
	"github.com/Iam54r1n4/Gordafarid/internal/config"
	"github.com/Iam54r1n4/Gordafarid/internal/logger"
	"github.com/Iam54r1n4/Gordafarid/internal/proxy_error"
)

// handleUserPassAuthMethodNegotiation handles the username/password authentication
// This follows the username/password authentication subnegotiation defined in RFC 1929
func (s *Socks5) handleUserPassAuthMethodNegotiation(cfg *config.ClientConfig) error {
	// Read authentication version
	buf := make([]byte, 1)
	if _, err := utils.ReadWithContext(s.ctx, s.conn, buf); err != nil {
		return errors.Join(proxy_error.ErrSocks5UnableToReadUserPassAuthVersion, err)
	}
	if buf[0] != userPassAuthVersion {
		return errors.Join(proxy_error.ErrSocks5UnsupportedUserPassAuthVersion, fmt.Errorf("sent version: %d", buf[0]))
	}
	s.userPassAuth.version = buf[0]

	// Read username
	if _, err := utils.ReadWithContext(s.ctx, s.conn, buf); err != nil {
		return errors.Join(proxy_error.ErrSocks5UnableToReadUserPassAuthUsernameLength, err)
	}
	s.userPassAuth.uLen = buf[0]
	s.userPassAuth.username = make([]byte, s.userPassAuth.uLen)
	if _, err := utils.ReadWithContext(s.ctx, s.conn, s.userPassAuth.username); err != nil {
		return errors.Join(proxy_error.ErrSocks5UnableToReadUserPassAuthUsername, err)
	}

	// Read password
	if _, err := utils.ReadWithContext(s.ctx, s.conn, buf); err != nil {
		return errors.Join(proxy_error.ErrSocks5UnableToReadUserPassAuthPasswordLength, err)
	}
	s.userPassAuth.pLen = buf[0]
	s.userPassAuth.password = make([]byte, s.userPassAuth.pLen)
	if _, err := utils.ReadWithContext(s.ctx, s.conn, s.userPassAuth.password); err != nil {
		return errors.Join(proxy_error.ErrSocks5UnableToReadUserPassAuthPassword, err)
	}

	logger.Debug(fmt.Sprintf("SOCKS5 authentication: username: %s, password: %s", string(s.userPassAuth.username), string(s.userPassAuth.password)))

	// Verify the credentials
	authErr := s.authenticate(cfg)
	// Send failed response if auth failed
	if authErr != nil {
		if err := s.sendTwoBytesResponse(userPassAuthVersion, userPassAuthFailed); err != nil {
			return errors.Join(proxy_error.ErrSocks5UnableToSendUserPassAuthFailedResponse, err)
		}
		return errors.Join(proxy_error.ErrSocks5AuthenticationFailed, fmt.Errorf("username: %s, password: %s", string(s.userPassAuth.username), string(s.userPassAuth.password)))
	}
	// Send success response
	if err := s.sendTwoBytesResponse(userPassAuthVersion, userPassAuthSuccess); err != nil {
		return errors.Join(proxy_error.ErrSocks5UnableToSendUserPassAuthSuccessResponse, err)
	}

	return nil
}
func (s *Socks5) verifyMethods(cfg *config.ClientConfig, bestMethod byte) error {
	// If username/password authentication is required and not supported, return an error
	if len(cfg.Socks5Credentials) > 0 && bestMethod != userPassAuthMethod {
		s.gretting.methods = []byte{noAcceptableMethod}
		return errors.Join(proxy_error.ErrSocks5InvalidNMethodsValue, fmt.Errorf("sent nmethods: %d", s.gretting.nMethods))
	}
	return nil
}

func (s *Socks5) authenticate(cfg *config.ClientConfig) error {
	p, ok := cfg.Socks5Credentials[string(s.userPassAuth.username)]
	if !ok {
		return proxy_error.ErrSocks5AuthIncorrectUsername
	}
	if string(s.userPassAuth.password) == p {
		return nil
	}
	return proxy_error.ErrSocks5AuthIncorrectUsername
}

// selectPreferredSocks5AuthMethod selects the preferred authentication method from the provided list.
//
// This function examines the list of authentication methods supported by the client
// and chooses the most appropriate one based on the following priority:
// 1. Username/Password Authentication (method 2)
// 2. No Authentication (method 0)
//
// If neither of these methods is supported, it returns an error indicating no acceptable methods.
//
// Parameters:
//   - methods: A byte slice containing the authentication methods supported by the client.
//
// Returns:
//   - byte: The selected authentication method (UserPassAuth, NoAuth, or NoAcceptableMethods).
//   - error: An error if no acceptable authentication method is found.
func (s *Socks5) selectPreferredSocks5AuthMethod() (byte, error) {
	noAuth, userPassAuth := false, false
	for _, method := range s.gretting.methods {
		if noAuth && userPassAuth {
			break
		}
		if method == noAuthMethod {
			noAuth = true
		} else if method == userPassAuthMethod {
			userPassAuth = true
		}
	}
	if userPassAuth {
		return userPassAuthMethod, nil
	}
	if noAuth {
		return noAuthMethod, nil
	}
	return noAcceptableMethod, errors.Join(proxy_error.ErrSocks5InvalidMethod, fmt.Errorf("sent auth methods: %v", s.gretting.methods))
}
