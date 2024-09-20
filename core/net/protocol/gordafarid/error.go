package gordafarid

import "errors"

var (
	// General errors
	errGordafaridHandshakeFailed     = errors.New("the Gordafarid handshake failed: protocol mismatch or authentication error")
	errGordafaridUnableToReadRequest = errors.New("unable to read the Gordafarid request")

	// Address type error
	errUnableToReadAddressType = errors.New("unable to read the Gordafarid address type")

	// Version errors
	errGordafaridUnableToReadVersion = errors.New("unable to read the Gordafarid version")
	errGordafaridUnsupportedVersion  = errors.New("unsupported the Gordafarid version")

	// Account hash errors
	errGordafaridUnableToReadAccountHash = errors.New("unable to read the Gordafarid account hash")
	errGordafaridInvalidAccountHash      = errors.New("invalid Gordafarid account hash")

	// Greeting errors
	errGordafaridGreetingFailed = errors.New("the Gordafarid greeting failed")

	// Cmd errors
	errGordafaridUnableToReadCmd = errors.New("unable to read the Gordafarid cmd")
	errGordafaridUnsupportedCmd  = errors.New("unsupported Gordafarid cmd")

	// Authentication errors
	errGordafaridAuthFailed = errors.New("the Gordafarid authentication failed")

	errGordafaridReplyFailed = errors.New("the reply response from the server indicates failure")
)
