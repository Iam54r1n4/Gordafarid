package proxy_error

import "errors"

// Connection errors
var (
	ErrConnectionClosed    = errors.New("connection unexpectedly closed")
	ErrConnectionAccepting = errors.New("failed to accept incoming connection")
)

// Socks5 errors
var (
	ErrSocks5HandshakeTimeout            = errors.New("SOCKS5 handshake timed out")
	ErrSocks5HandshakeFailed             = errors.New("SOCKS5 handshake failed: protocol mismatch or authentication error")
	ErrSocks5UnsupportedVersion          = errors.New("unsupported SOCKS5 version")
	ErrSocks5UnableToReadVersion         = errors.New("unable to read SOCKS5 version")
	ErrSocks5UnableToDiscardNMethods     = errors.New("unable to discard SOCKS5 nmethods")
	ErrSocks5UnableToSendVersionResponse = errors.New("unable to send SOCKS5 version response(first response)") // First response
	ErrSocks5UnableToReadRequest         = errors.New("unable to read SOCKS5 request")
	ErrSocks5UnsupportedVersionOrCommand = errors.New("unsupported SOCKS5 version or command(in handshake request)")
	ErrSocks5UnableToReadAddressType     = errors.New("unable to read address type")
	ErrSocks5UnsupportedAddressType      = errors.New("unsupported SOCKS5 address type")
	ErrSocks5UnableToReadIpv4            = errors.New("unable to read IPv4 address")
	ErrSocks5UnableToReadIpv6            = errors.New("unable to read IPv6 address")
	ErrSocks5UnableToReadDomain          = errors.New("unable to read domain name")
	ErrSocks5UnableToReadPort            = errors.New("unable to read port")
	ErrSocks5UnableToSendSuccessResponse = errors.New("unable to send success response(second response)") // Second response
)

// Listening errors
var (
	ErrServerListenFailed       = errors.New("server failed to start listening on specified address")
	ErrClientListenFailed       = errors.New("client failed to start listening on specified address")
	ErrServerDialFailed         = errors.New("server failed to establish connection with target")
	ErrClientToServerDialFailed = errors.New("client failed to establish connection with proxy server")
)

// Copying errors
var ErrTransferError = errors.New("data transfer failed between client and server")

// Crypto errors
var ErrChacha20poly1305Failed = errors.New("encryption/decryption failed using ChaCha20-Poly1305")
