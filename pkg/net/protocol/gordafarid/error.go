package gordafarid

import "errors"

var (
	// General errors
	errHandshakeFailed = errors.New("the Gordafarid handshake failed: protocol mismatch or authentication error")

	// Initial greeting errors
	errServerFailedToHandleInitialGreeting         = errors.New("failed to send the Gordafarid initial greeting")
	errServerFailedToSendGreetingFailedResponse    = errors.New("failed to send the Gordafarid initial greeting failed response")
	errServerFailedToSendGreetingSuccessResponse   = errors.New("failed to send the Gordafarid initial greeting succeeded response")
	errServerFailedToReadEncryptedInitialGreeting  = errors.New("failed to read the Gordafarid client's encrypted initial greeting")
	errServerFailedToDecryptInitialGreeting        = errors.New("failed to decrypt the Gordafarid client's initial greeting")
	errClientFailedToSendInitialGreeting           = errors.New("failed to send the Gordafarid initial greeting")
	errClientFailedToHandleInitialGreetingResponse = errors.New("failed to handle the Gordafarid greeting response")
	errClientFailedToEncryptInitialGreeting        = errors.New("failed to encrypt the Gordafarid initial greeting")

	// Crypto errors
	errFailedToBuildAEADCipher = errors.New("failed to build the Gordafarid AEAD cipher")

	// Request errors
	errServerFailedToHandleRequest = errors.New("failed to handle the Gordafarid request")
	errClientFailedToSendRequest   = errors.New("failed to send the Gordafarid request")

	// Reply errors
	errServerFailedToSendReplyResponse   = errors.New("failed to send the Gordafarid reply response")
	errClientFailedToHandleReplyResponse = errors.New("failed to handle the Gordafarid reply response")

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
