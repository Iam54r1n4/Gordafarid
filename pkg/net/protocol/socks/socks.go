// Package socks implements the server side SOCKS5 proxy protocol.
package socks

import (
	"context"
	"net"
	"time"
)

// ServerCredentials is a map that stores username-password pairs for authentication.
type ServerCredentials map[string]string

// ServerConfig holds the configuration for the SOCKS5 server.
type ServerConfig struct {
	credentials      ServerCredentials
	handshakeTimeout int // In seconds
}

// NewServerConfig creates and returns a new ServerConfig with the given credentials and handshake timeout.
func NewServerConfig(credentials ServerCredentials, handshakeTimeout int) *ServerConfig {
	return &ServerConfig{
		credentials:      credentials,
		handshakeTimeout: handshakeTimeout,
	}
}

// Listener wraps a net.Listener and associates it with a ServerConfig.
type Listener struct {
	net.Listener
	config *ServerConfig
}

// NewListener creates a new TCP listener with the given local address and ServerConfig.
func NewListener(laddr string, config *ServerConfig) (*Listener, error) {
	ln, err := net.Listen("tcp", laddr)
	if err != nil {
		return nil, err
	}
	return &Listener{
		Listener: ln,
		config:   config,
	}, nil
}

// NewWrapListener wraps an existing net.Listener with a ServerConfig.
func NewWrapListener(inner net.Listener, config *ServerConfig) *Listener {
	return &Listener{
		Listener: inner,
		config:   config,
	}
}

// Accept waits for and returns the next connection to the listener.
// It performs the SOCKS5 handshake before returning the connection.
func (l *Listener) Accept() (*Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	sc := buildServerConn(c, l.config)
	handshakeCtx, cancel := context.WithTimeout(context.Background(), time.Duration(l.config.handshakeTimeout)*time.Second)
	defer cancel()
	if err = sc.handshakeContext(handshakeCtx); err != nil {
		sc.Close()
		return nil, err
	}
	return sc, nil
}

// buildServerConn creates a new Conn instance for the server side of the SOCKS5 connection.
func buildServerConn(c net.Conn, serverConfig *ServerConfig) *Conn {
	sc := &Conn{
		Conn:         c,
		serverConfig: serverConfig,
		isClient:     false,
	}
	sc.handshakeFn = sc.serverHandshake
	return sc
}
