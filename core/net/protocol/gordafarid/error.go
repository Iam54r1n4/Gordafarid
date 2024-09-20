package gordafarid

import "errors"

var (
	// General errors
	errHandshakeFailed = errors.New("the Gordafarid handshake failed: protocol mismatch or authentication error")

	// Address type error
	errUnableToReadAddressType = errors.New("unable to read the Gordafarid address type")

	// Version errors
	errUnableToReadVersion = errors.New("unable to read the Gordafarid version")
	errUnsupportedVersion  = errors.New("unsupported the Gordafarid version")

	// Account hash errors
	errUnableToReadAccountHash = errors.New("unable to read the Gordafarid account hash")
	errInvalidAccountHash      = errors.New("invalid Gordafarid account hash")

	// Greeting errors
	errGreetingFailed = errors.New("the Gordafarid greeting failed")

	// Cmd errors
	errUnableToReadCmd = errors.New("unable to read the Gordafarid cmd")
	errUnsupportedCmd  = errors.New("unsupported Gordafarid cmd")

	// Authentication errors
	errAuthFailed = errors.New("the Gordafarid authentication failed")

	errReplyFailed = errors.New("the reply response from the server indicates failure")
)
