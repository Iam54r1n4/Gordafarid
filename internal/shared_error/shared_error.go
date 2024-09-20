package shared_error

import "errors"

var (
	ErrServerListenFailed       = errors.New("server failed to start listening on specified address")
	ErrClientListenFailed       = errors.New("client failed to start listening on specified address")
	ErrServerDialFailed         = errors.New("server failed to establish connection with target")
	ErrClientToServerDialFailed = errors.New("client failed to establish connection with proxy server")
	ErrListenerIsNotInitialized = errors.New("listener is not initialized")
	ErrConnectionClosed         = errors.New("connection unexpectedly closed")
	ErrConnectionAccepting      = errors.New("failed to accept incoming connection")
)
