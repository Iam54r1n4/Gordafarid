package socks

import "errors"

var (
	// General errors
	errUnableToReadRequest     = errors.New("unable to read the SOCKS5 request")
	errUnableToReadAddressType = errors.New("unable to read the SOCKS5 address type")

	// Initial greeting errors
	errFailedToHandleInitialGreeting       = errors.New("failed to handle the initial greeting")
	errFailedToParseInitialGreetingHeaders = errors.New("failed to parse initial greeting headers")

	// Request errors
	errFailedToHandleRequest       = errors.New("failed to handle the request")
	errFailedToParseRequestHeaders = errors.New("failed to parse request headers")

	// Reply errors
	errFailedToSendReplyResponse = errors.New("failed to send reply response")
	// Auth
	errAuthenticationFailed  = errors.New("the SOCkS5 authentication failed")
	errAuthIncorrectUsername = errors.New("username is incorrect")
	errAuthIncorrectPassword = errors.New("password is incorrect")

	// Version errors
	errUnsupportedVersion  = errors.New("unsupported the SOCKS5 version")
	errUnableToReadVersion = errors.New("unable to read the SOCKS5 version")

	// Send errors
	errUnableToSendMethodSelectionResponse     = errors.New("unable to send the SOCKS5 version response(first response)")  // First response
	errUnableToSendReplyResponse               = errors.New("unable to send the SOCKS5 success response(second response)") // Second response
	errUnableToSendUserPassAuthSuccessResponse = errors.New("unable to send the SOCKS5 username/password authentication success response")
	errUnableToSendUserPassAuthFailedResponse  = errors.New("unable to send the SOCKS5 username/password authentication failed response")

	// CMD errors
	errUnsupportedVersionOrCommand = errors.New("unsupported SOCKS5 version or command(in handshake request)")

	// Authentication errors
	errInvalidNMethodsValue = errors.New("invalid SOCKS5 nmethods value")
	errInvalidMethod        = errors.New("invalid SOCKS5 method")
	errNoAcceptableMethod   = errors.New("SOCKS5 no acceptable method")

	// Method selection errors
	errFailedToSendMethodSelectionResponse    = errors.New("failed to send the SOCKS5 version response")
	errFailedToSendNoAcceptableMethodResponse = errors.New("failed to send SOCKS5 no acceptable method")
	errFailedToVerifyMethods                  = errors.New("failed to verify SOCKS5 methods")

	// Username/Password authentication mehtod negotiation errors
	errUnableToReadUserPassAuthVersion        = errors.New("unable to read the SOCKS5 username/password authenticaation version")
	errUnsupportedUserPassAuthVersion         = errors.New("unsupported the SOCKS5 username/password authentication version")
	errUnableToReadUserPassAuthUsernameLength = errors.New("unable to read the SOCKS5 username/password authentication username length")
	errUnableToReadUserPassAuthUsername       = errors.New("unable to read the SOCKS5 username/password authentication username")
	errUnableToReadUserPassAuthPasswordLength = errors.New("unable to read the SOCKS5 username/password authentication password length")
	errUnableToReadUserPassAuthPassword       = errors.New("unable to read the SOCKS5 username/password authentication password")
	errFailedToHandleUserPassAuthNegotiation  = errors.New("failed to handle SOCKS5 user/pass auth negotiation")
)
