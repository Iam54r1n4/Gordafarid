package proxy_error

import "errors"

// Config errors
var (
	ErrInvalidConfigFile          = errors.New("invalid config file")
	ErrCryptoAlgorithmEmpty       = errors.New("crypto.algorithm is empty")
	ErrCryptoAlgorithmUnsupported = errors.New("crypto.algorithm is not supported")
	ErrCryptoInitFailed           = errors.New("the crypto initialization failed")
	ErrAccountPasswordInvalid     = errors.New("account.password length is invalid, must sync to selected crypto algorithm key length")
	ErrEmptyServerCredentials     = errors.New("server.credentials is empty")
)

// Listening errors
var (
	ErrServerListenFailed       = errors.New("server failed to start listening on specified address")
	ErrClientListenFailed       = errors.New("client failed to start listening on specified address")
	ErrServerDialFailed         = errors.New("server failed to establish connection with target")
	ErrClientToServerDialFailed = errors.New("client failed to establish connection with proxy server")
	ErrListenerIsNotInitialized = errors.New("listener is not initialized")
)

// Connection errors
var (
	ErrConnectionClosed    = errors.New("connection unexpectedly closed")
	ErrConnectionAccepting = errors.New("failed to accept incoming connection")
	ErrTransferError       = errors.New("data transfer failed between client and server")
)

var ErrBufferedConnBufferIsEmpty = errors.New("the BufferedConn internal buffer is empty")

// Socks5 errors
var (
	// General errors
	ErrSocks5HandshakeTimeout    = errors.New("the SOCKS5 handshake timed out")
	ErrSocks5HandshakeFailed     = errors.New("the SOCKS5 handshake failed: protocol mismatch or authentication error")
	ErrSocks5UnableToReadRequest = errors.New("unable to read the SOCKS5 request")

	// Auth
	ErrSocks5AuthenticationFailed  = errors.New("the SOCkS5 authentication failed")
	ErrSocks5AuthIncorrectUsername = errors.New("username is incorrect")
	ErrSocks5AuthIncorrectPassword = errors.New("password is incorrect")

	// Validation errors
	ErrSocks5ClientSideInitialGreetingFailed = errors.New("client side the SOCKS5 initial greeting failed")
	ErrSocks5ClientSideInitialGreetingEmpty  = errors.New("client side the SOCKS5 initial greeting is empty")

	// Version errors
	ErrSocks5UnsupportedVersion  = errors.New("unsupported the SOCKS5 version")
	ErrSocks5UnableToReadVersion = errors.New("unable to read the SOCKS5 version")

	// Send errors
	ErrSocks5UnableToSendVersionResponse             = errors.New("unable to send the SOCKS5 version response(first response)")  // First response
	ErrSocks5UnableToSendSuccessResponse             = errors.New("unable to send the SOCKS5 success response(second response)") // Second response
	ErrSocks5UnableToSendUserPassAuthSuccessResponse = errors.New("unable to send the SOCKS5 username/password authentication success response")
	ErrSocks5UnableToSendUserPassAuthFailedResponse  = errors.New("unable to send the SOCKS5 username/password authentication failed response")

	// CMD errors
	ErrSocks5UnsupportedVersionOrCommand = errors.New("unsupported SOCKS5 version or command(in handshake request)")

	// Read network addresses errors
	ErrSocks5UnableToReadAddressType = errors.New("unable to read the SOCKS5 address type")
	ErrSocks5UnsupportedAddressType  = errors.New("unsupported the SOCKS5 address type")
	ErrSocks5UnableToReadIpv4        = errors.New("unable to read the SOCKS5 IPv4 address")
	ErrSocks5UnableToReadIpv6        = errors.New("unable to read the SOCKS5 IPv6 address")
	ErrSocks5UnableToReadDomain      = errors.New("unable to read the SOCKS5 domain name")
	ErrSocks5UnableToReadPort        = errors.New("unable to read the SOCKS5 port")

	// Authentication errors
	ErrSocks5InvalidNMethodsValue = errors.New("invalid SOCKS5 nmethods value")
	ErrSocks5InvalidMethod        = errors.New("invalid SOCKS5 method")
	ErrSocks5NoAcceptableMethod   = errors.New("no acceptable method")

	// Username/Password authentication mehtod negotiation errors
	ErrSocks5UnableToReadUserPassAuthVersion        = errors.New("unable to read the SOCKS5 username/password authenticaation version")
	ErrSocks5UnsupportedUserPassAuthVersion         = errors.New("unsupported the SOCKS5 username/password authentication version")
	ErrSocks5UnableToReadUserPassAuthUsernameLength = errors.New("unable to read the SOCKS5 username/password authentication username length")
	ErrSocks5UnableToReadUserPassAuthUsername       = errors.New("unable to read the SOCKS5 username/password authentication username")
	ErrSocks5UnableToReadUserPassAuthPasswordLength = errors.New("unable to read the SOCKS5 username/password authentication password length")
	ErrSocks5UnableToReadUserPassAuthPassword       = errors.New("unable to read the SOCKS5 username/password authentication password")
)

// Gordafarid errors
var (
	// General errors
	ErrGordafaridHandshakeTimeout    = errors.New("the Gordafarid handshake timed out")
	ErrGordafaridHandshakeFailed     = errors.New("the Gordafarid handshake failed: protocol mismatch or authentication error")
	ErrGordafaridUnableToReadRequest = errors.New("unable to read the Gordafarid request")
	// Version errors
	ErrGordafaridUnableToReadVersion = errors.New("unable to read the Gordafarid version")
	ErrGordafaridUnsupportedVersion  = errors.New("unsupported the Gordafarid version")

	// Account hash errors
	ErrGordafaridUnableToReadAccountHash = errors.New("unable to read the Gordafarid account hash")
	ErrGordafaridInvalidAccountHash      = errors.New("invalid Gordafarid account hash")
	// Cmd errors
	ErrGordafaridUnableToReadCmd  = errors.New("unable to read the Gordafarid cmd")
	ErrGordafaridInvalidCmd       = errors.New("invalid Gordafarid cmd")
	ErrGordafaridUnableToReadAytp = errors.New("unable to read the Gordafarid address type")
)
