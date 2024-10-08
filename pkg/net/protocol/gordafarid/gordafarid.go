// Package gordafarid implements the Gordafarid protocol, a custom network protocol for secure communication.
package gordafarid

import (
	"context"
	"crypto/sha256"
	"errors"
	"net"
	"time"

	"github.com/Iam54r1n4/Gordafarid/pkg/net/protocol"
)

// Hash represents a SHA-256 hash value.
type Hash [HashSize]byte

const InitPasswordSize = 32

// Listener wraps a net.Listener with Gordafarid-specific functionality.
type Listener struct {
	net.Listener
	config *Config
}

// Credential represents a username and password pair for authentication.
type Credential struct {
	Username string
	Password string
}

// NewCredential creates a new Credential instance with the given username and password.
func NewCredential(username, password string) Credential {
	return Credential{
		Username: username,
		Password: password,
	}
}

// ServerConfig holds the configuration options for a Gordafarid server.
type ServerConfig struct {
	Credentials         []Credential // Server-side credentials for authentication
	EncryptionAlgorithm string       // Encryption algorithm to be used
	InitPassword        string       // Initial password for decrypting the client's initial greeting
	HandshakeTimeout    int          // Server handshake timeout in seconds
}

// NewServerConfig creates a new ServerConfig instance with the provided parameters.
func NewServerConfig(credentials []Credential, encryptionAlgorithm, initPassword string, handshakeTimeout int) *ServerConfig {
	return &ServerConfig{
		Credentials:         credentials,
		EncryptionAlgorithm: encryptionAlgorithm,
		InitPassword:        initPassword,
		HandshakeTimeout:    handshakeTimeout,
	}
}

// convertToRealConfig transforms the ServerConfig into an internal serverConfig structure.
func (scc *ServerConfig) convertToRealConfig() *Config {
	var realConfig Config
	realConfig.serverCredentials = make(serverCredentials, len(scc.Credentials))

	for _, item := range scc.Credentials {
		hash := sha256.Sum256([]byte(item.Username + item.Password))
		realConfig.serverCredentials[hash] = []byte(item.Password)
	}
	realConfig.encryptionAlgorithm = scc.EncryptionAlgorithm
	copy(realConfig.initPassword[:], []byte(scc.InitPassword))
	realConfig.handshakeTimeout = scc.HandshakeTimeout
	return &realConfig
}

// serverCredentials is a map of hashed credentials to passwords.
type serverCredentials map[Hash][]byte

// Config holds the internal connection's configuration.
type Config struct {
	serverCredentials   serverCredentials
	encryptionAlgorithm string
	initPassword        [InitPasswordSize]byte // Initial password for decrypting the client's initial greeting
	handshakeTimeout    int                    // Server handshake timeout in seconds
}

// NewListener creates a new Gordafarid Listener wrapping the provided net.Listener.
func NewListener(underlyingListener net.Listener, config *ServerConfig) *Listener {
	return &Listener{
		Listener: underlyingListener,
		config:   config.convertToRealConfig(),
	}
}

// Accept waits for and returns the next connection to the listener.
func (l *Listener) Accept() (*Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	gc := buildServerConn(c, l.config)
	handshakeCtx, cancel := context.WithTimeout(context.Background(), time.Duration(l.config.handshakeTimeout)*time.Second)
	defer cancel()
	if err = gc.handshakeContext(handshakeCtx); err != nil {
		gc.Close()
		return nil, err
	}

	return gc, nil
}

// Listen creates a new Gordafarid listener on the specified network address.
func Listen(laddr string, config *ServerConfig) (*Listener, error) {
	ln, err := net.Listen("tcp", laddr)
	if err != nil {
		return nil, err
	}
	return NewListener(ln, config), nil
}

// dialAccountConfig holds the configuration for client-side authentication.
type dialAccountConfig struct {
	Account         Credential
	InitPassword    [InitPasswordSize]byte // Client side init password for encrypting the client's initial greeting
	CryptoAlgorithm string
}

// NewDialAccountConfig creates a new DialAccountConfig instance.
func NewDialAccountConfig(account Credential, initPassword, cryptoAlgorithm string) *dialAccountConfig {
	d := &dialAccountConfig{
		Account:         account,
		CryptoAlgorithm: cryptoAlgorithm,
	}
	copy(d.InitPassword[:], []byte(initPassword))
	return d
}

// dialConnConfig holds the configuration for the connection destination.
type dialConnConfig struct {
	protocol.AddressHeader
}

// NewDialConnConfig creates a new DialConnConfig instance.
func NewDialConnConfig(addr *protocol.AddressHeader) *dialConnConfig {
	return &dialConnConfig{
		AddressHeader: *addr,
	}
}

// Dialer represents a Gordafarid dialer for establishing connections.
type Dialer struct {
	net.Dialer
	accountConfig *dialAccountConfig
	connConfig    *dialConnConfig
}

// NewDialer creates a new Gordafarid Dialer instance.
func NewDialer(accountConfig *dialAccountConfig, connConfig *dialConnConfig) *Dialer {
	return &Dialer{
		accountConfig: accountConfig,
		connConfig:    connConfig,
	}
}

// dialTCP establishes a TCP connection to the specified address.
func (d *Dialer) dialTCP(ctx context.Context, addr string) (net.Conn, error) {
	tcpConn, err := d.Dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	return tcpConn, nil
}

// dial performs the Gordafarid handshake over an established TCP connection.
func (d *Dialer) dial(ctx context.Context, dialConnConfig *dialConnConfig, tcpConn net.Conn) (net.Conn, error) {
	var conn *Conn
	if dialConnConfig != nil {
		conn = buildClientConn(tcpConn, d.accountConfig, dialConnConfig)
	} else {
		conn = buildClientConn(tcpConn, d.accountConfig, d.connConfig)
	}

	// TODO: it's for debugging, logically, it's not necessary
	if conn == nil {
		panic("the connection is nil in the Gordafarid Dialer's dial method")
	}

	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, errors.Join(errHandshakeFailed, err)
	}

	return conn, nil
}

// Dial establishes a Gordafarid connection to the specified address.
func (d *Dialer) Dial(dialConnConfig *dialConnConfig, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), dialConnConfig, addr)
}

// DialContext establishes a Gordafarid connection to the specified address with the given context.
func (d *Dialer) DialContext(ctx context.Context, dialConnConfig *dialConnConfig, addr string) (net.Conn, error) {
	tcpConn, err := d.dialTCP(ctx, addr)
	if err != nil {
		return nil, err
	}
	return d.dial(ctx, dialConnConfig, tcpConn)
}

// WrapTCPContext wraps an existing TCP connection with Gordafarid protocol.
func (d *Dialer) WrapTCPContext(ctx context.Context, dialConnConfig *dialConnConfig, conn net.Conn) (net.Conn, error) {
	return d.dial(ctx, dialConnConfig, conn)
}

// WrapTCP wraps an existing TCP connection with Gordafarid protocol using the background context.
func (d *Dialer) WrapTCP(dialConnConfig *dialConnConfig, conn net.Conn) (net.Conn, error) {
	return d.WrapTCPContext(context.Background(), dialConnConfig, conn)
}

// DialContext establishes a Gordafarid connection with the given context and configuration.
func DialContext(ctx context.Context, addr string, dialAccountConfig *dialAccountConfig, dialConnConfig *dialConnConfig) (net.Conn, error) {
	d := NewDialer(dialAccountConfig, dialConnConfig)
	tcpConn, err := d.dialTCP(ctx, addr)
	if err != nil {
		return nil, err
	}
	return d.dial(ctx, nil, tcpConn)
}

// Dial establishes a Gordafarid connection using the background context.
func Dial(addr string, dialAccountConfig *dialAccountConfig, dialConnConfig *dialConnConfig) (net.Conn, error) {
	return DialContext(context.Background(), addr, dialAccountConfig, dialConnConfig)
}

// WrapTCPContext wraps an existing TCP connection with Gordafarid protocol using the given context.
func WrapTCPContext(ctx context.Context, conn net.Conn, dialAccountConfig *dialAccountConfig, dialConnConfig *dialConnConfig) (net.Conn, error) {
	d := NewDialer(dialAccountConfig, dialConnConfig)
	return d.dial(ctx, nil, conn)
}

// WrapTCP wraps an existing TCP connection with Gordafarid protocol using the background context.
func WrapTCP(conn net.Conn, dialAccountConfig *dialAccountConfig, dialConnConfig *dialConnConfig) (net.Conn, error) {
	return WrapTCPContext(context.Background(), conn, dialAccountConfig, dialConnConfig)
}

// buildClientConn creates a new Gordafarid client connection from an underlying TCP connection.
func buildClientConn(underlyingConn net.Conn, dialAccountConfig *dialAccountConfig, dialConnConfig *dialConnConfig) *Conn {
	accountHash := sha256.Sum256([]byte(dialAccountConfig.Account.Username + dialAccountConfig.Account.Password))

	c := &Conn{
		Conn:     underlyingConn,
		isClient: true,
		config: &Config{
			encryptionAlgorithm: dialAccountConfig.CryptoAlgorithm,
			initPassword:        dialAccountConfig.InitPassword,
		},
		account: account{
			hash:     accountHash,
			password: []byte(dialAccountConfig.Account.Password),
		},
		greeting: greetingHeader{
			hash: accountHash,
			BasicHeader: protocol.BasicHeader{
				Version: gordafaridVersion,
				Cmd:     protocol.CmdConnect,
			},
		},
		request: requestHeader{
			AddressHeader: protocol.AddressHeader{
				Atyp:    dialConnConfig.Atyp,
				DstAddr: dialConnConfig.DstAddr,
				DstPort: dialConnConfig.DstPort,
			},
		},
	}
	c.handshakeFn = c.clientHandshake
	return c
}

// buildServerConn creates a new Gordafarid server connection from an underlying TCP connection.
func buildServerConn(underlyingConn net.Conn, config *Config) *Conn {
	c := &Conn{
		Conn:     underlyingConn,
		config:   config,
		isClient: false,
	}
	c.handshakeFn = c.serverHandshake
	return c
}
