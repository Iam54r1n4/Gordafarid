package socks

import "errors"

var (
	// General errors
	errSocks5UnableToReadRequest = errors.New("unable to read the SOCKS5 request")
	errUnableToReadAddressType   = errors.New("unable to read the SOCKS5 address type")

	// Auth
	errSocks5AuthenticationFailed  = errors.New("the SOCkS5 authentication failed")
	errSocks5AuthIncorrectUsername = errors.New("username is incorrect")
	errSocks5AuthIncorrectPassword = errors.New("password is incorrect")

	// Version errors
	errSocks5UnsupportedVersion  = errors.New("unsupported the SOCKS5 version")
	errSocks5UnableToReadVersion = errors.New("unable to read the SOCKS5 version")

	// Send errors
	errSocks5UnableToSendMethodSelectionResponse     = errors.New("unable to send the SOCKS5 version response(first response)")  // First response
	errSocks5UnableToSendReplyResponse               = errors.New("unable to send the SOCKS5 success response(second response)") // Second response
	errSocks5UnableToSendUserPassAuthSuccessResponse = errors.New("unable to send the SOCKS5 username/password authentication success response")
	errSocks5UnableToSendUserPassAuthFailedResponse  = errors.New("unable to send the SOCKS5 username/password authentication failed response")

	// CMD errors
	errSocks5UnsupportedVersionOrCommand = errors.New("unsupported SOCKS5 version or command(in handshake request)")

	// Authentication errors
	errSocks5InvalidNMethodsValue = errors.New("invalid SOCKS5 nmethods value")
	errSocks5InvalidMethod        = errors.New("invalid SOCKS5 method")
	errSocks5NoAcceptableMethod   = errors.New("no acceptable method")

	// Username/Password authentication mehtod negotiation errors
	errSocks5UnableToReadUserPassAuthVersion        = errors.New("unable to read the SOCKS5 username/password authenticaation version")
	errSocks5UnsupportedUserPassAuthVersion         = errors.New("unsupported the SOCKS5 username/password authentication version")
	errSocks5UnableToReadUserPassAuthUsernameLength = errors.New("unable to read the SOCKS5 username/password authentication username length")
	errSocks5UnableToReadUserPassAuthUsername       = errors.New("unable to read the SOCKS5 username/password authentication username")
	errSocks5UnableToReadUserPassAuthPasswordLength = errors.New("unable to read the SOCKS5 username/password authentication password length")
	errSocks5UnableToReadUserPassAuthPassword       = errors.New("unable to read the SOCKS5 username/password authentication password")
)
