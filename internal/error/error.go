package proxy_error

import "errors"

// Connection errors
var ErrConnectionClosed error = errors.New("connection unexpectedly closed")
var ErrConnectionAccepting error = errors.New("failed to accept incoming connection")
var ErrSocks5HandshakeTimeout error = errors.New("SOCKS5 handshake timed out")
var ErrSocks5HandshakeFailed error = errors.New("SOCKS5 handshake failed: protocol mismatch or authentication error")

// Listening errors
var ErrServerListenFailed error = errors.New("server failed to start listening on specified address")
var ErrClientListenFailed error = errors.New("client failed to start listening on specified address")
var ErrServerDialFailed error = errors.New("server failed to establish connection with target")
var ErrClientToServerDialFailed error = errors.New("client failed to establish connection with proxy server")

// Copying errors
var ErrTransferError error = errors.New("data transfer failed between client and server")

// Crypto errors
var ErrChacha20poly1305Failed error = errors.New("encryption/decryption failed using ChaCha20-Poly1305")
