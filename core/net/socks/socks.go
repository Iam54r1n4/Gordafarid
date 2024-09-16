// Package socks implements the SOCKS5 proxy protocol.
package socks

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/Iam54r1n4/Gordafarid/core/net/utils"
	"github.com/Iam54r1n4/Gordafarid/internal/proxy_error"
)

// Constants for SOCKS5 protocol
const (
	// socks5Version represents the SOCKS protocol version (SOCKS5)
	socks5Version = 5

	// Address types
	AtypIPv4   = 1 // IPv4 address
	AtypDomain = 3 // Domain name
	AtypIPv6   = 4 // IPv6 address

	// Authentication methods
	noAuthMethod       = 0x00 // No authentication required
	userPassAuthMethod = 0x02 // Username/password authentication
	noAcceptableMethod = 0xFF // No acceptable method

	// User/Pass authentication constants
	userPassAuthVersion = 0x01 // Username/password authentication version
	userPassAuthSuccess = 0x00 // Authentication success
	userPassAuthFailed  = 0x01 // Authentication failed

	MaxInitialGreetingSize = 1 + 1 + 256 // Max size of initial greeting
)

// HandshakeChan is used to communicate the result of the handshake
type HandshakeChan struct {
	TAddr string // Target address
	ATyp  byte   // Address type
	Err   error  // Error, if any
}

// ValidateSocks5 performs a quick validation of the SOCKS5 connection
func ValidateSocks5(timeoutMilliseconds int, c net.Conn) error {
	validationCtx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutMilliseconds)*time.Millisecond)
	defer cancel()
	_, err := handleInitialGreeting(validationCtx, c)
	return err
}

// Handshake performs the SOCKS5 handshake process
// This function follows the SOCKS5 protocol as defined in RFC 1928 and RFC 1929
// https://www.ietf.org/rfc/rfc1928.txt
// https://www.ietf.org/rfc/rfc1929.txt
// It handles the initial greeting, method selection, authentication (if required), and the SOCKS5 request

// Client -> Server: Initial Greeting
// +----+----------+----------+
// |VER | NMETHODS | METHODS  |
// +----+----------+----------+
// | 1  |    1     | 1 to 255 |
// +----+----------+----------+

// Server -> Client: Method Selection
// +----+--------+
// |VER | METHOD |
// +----+--------+
// | 1  |   1    |
// +----+--------+

// If USERNAME/PASSWORD authentication is selected:
// Client -> Server: Username/Password Authentication
// +----+------+----------+------+----------+
// |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
// +----+------+----------+------+----------+
// | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
// +----+------+----------+------+----------+

// Server -> Client: Authentication Response
// +----+--------+
// |VER | STATUS |
// +----+--------+
// | 1  |   1    |
// +----+--------+

// Client -> Server: SOCKS5 Request
// +----+-----+-------+------+----------+----------+
// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
// +----+-----+-------+------+----------+----------+
// | 1  |  1  | X'00' |  1   | Variable |    2     |
// +----+-----+-------+------+----------+----------+

// Server -> Client: SOCKS5 Reply
// +----+-----+-------+------+----------+----------+
// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
// +----+-----+-------+------+----------+----------+
// | 1  |  1  | X'00' |  1   | Variable |    2     |
// +----+-----+-------+------+----------+----------+

// VER: SOCKS version (0x05 for SOCKS5)
// NMETHODS: Number of authentication methods supported
// METHODS: Authentication methods supported
// CMD: Command (0x01 for CONNECT, 0x02 for BIND, 0x03 for UDP ASSOCIATE)
// RSV: Reserved byte, must be 0x00
// ATYP: Address type (0x01 for IPv4, 0x03 for Domain, 0x04 for IPv6)
// DST.ADDR: Destination address
// DST.PORT: Destination port
// REP: Reply field (0x00 for success, other values for various errors)
// BND.ADDR: Server bound address
// BND.PORT: Server bound port
// ULEN: Username length
// UNAME: Username
// PLEN: Password length
// PASSWD: Password
// STATUS: Authentication status (0x00 for success, 0x01 for failure)
func Handshake(ctx context.Context, c net.Conn, hChan chan<- HandshakeChan) {
	defer close(hChan)

	// Step 1: Handle initial greeting and method selection
	method, err := handleInitialGreeting(ctx, c)
	if err != nil {
		hChan <- HandshakeChan{Err: err}
		return
	}

	// Step 2: Send method selection message
	if err := sendTwoBytesResponse(c, socks5Version, method); err != nil {
		hChan <- HandshakeChan{Err: err}
		return
	}

	// Step 3: Handle authentication if required
	if method == userPassAuthMethod {
		if err := handleUserPassAuthMethodNegotiation(ctx, c); err != nil {
			hChan <- HandshakeChan{Err: err}
			return
		}
	}

	// Step 4: Handle SOCKS5 request
	atyp, taddr, err := handleSocks5Request(ctx, c)
	if err != nil {
		hChan <- HandshakeChan{Err: err}
		return
	}

	// Step 5: Send success response
	if err := sendSocks5SuccessResponse(c); err != nil {
		hChan <- HandshakeChan{Err: err}
		return
	}

	// Step 6: Return successful handshake result
	hChan <- HandshakeChan{TAddr: taddr, ATyp: atyp}
}

// handleInitialGreeting processes the initial SOCKS5 greeting from the client
// It reads the client's supported authentication methods and selects one
func handleInitialGreeting(ctx context.Context, c net.Conn) (byte, error) {
	// Read SOCKS version and number of methods
	buf := make([]byte, 2)
	if _, err := utils.ReadWithContext(ctx, c, buf); err != nil {
		return noAcceptableMethod, errors.Join(proxy_error.ErrSocks5UnableToReadVersion, err)
	}

	// Verify SOCKS version
	if buf[0] != socks5Version {
		return noAcceptableMethod, errors.Join(proxy_error.ErrSocks5UnsupportedVersion, fmt.Errorf("sent version: %d", buf[0]))
	}

	// Verify number of methods
	nMethods := buf[1]
	if nMethods == 0 {
		return noAcceptableMethod, errors.Join(proxy_error.ErrSocks5InvalidNMethodsValue, fmt.Errorf("sent nmethods: %d", nMethods))
	}

	// Read authentication methods
	methods := make([]byte, nMethods)
	if _, err := utils.ReadWithContext(ctx, c, methods); err != nil {
		return noAcceptableMethod, errors.Join(proxy_error.ErrSocks5InvalidNMethodsValue, fmt.Errorf("sent nmethods: %d", nMethods), err)
	}

	// Select preferred authentication method
	return selectPreferredSocks5AuthMethod(methods)
}

// selectPreferredSocks5AuthMethod selects the preferred authentication method from the provided list.
//
// This function examines the list of authentication methods supported by the client
// and chooses the most appropriate one based on the following priority:
// 1. Username/Password Authentication (method 2)
// 2. No Authentication (method 0)
//
// If neither of these methods is supported, it returns an error indicating no acceptable methods.
//
// Parameters:
//   - methods: A byte slice containing the authentication methods supported by the client.
//
// Returns:
//   - byte: The selected authentication method (UserPassAuth, NoAuth, or NoAcceptableMethods).
//   - error: An error if no acceptable authentication method is found.
func selectPreferredSocks5AuthMethod(methods []byte) (byte, error) {
	noAuth, userPassAuth := false, false
	for _, method := range methods {
		if noAuth && userPassAuth {
			break
		}
		if method == noAuthMethod {
			noAuth = true
		} else if method == userPassAuthMethod {
			userPassAuth = true
		}
	}
	if userPassAuth {
		return userPassAuthMethod, nil
	}
	if noAuth {
		return noAuthMethod, nil
	}
	return noAcceptableMethod, errors.Join(proxy_error.ErrSocks5InvalidMethod, fmt.Errorf("sent auth methods: %v", methods))
}

// handleUserPassAuthMethodNegotiation handles the username/password authentication
// This follows the username/password authentication subnegotiation defined in RFC 1929
func handleUserPassAuthMethodNegotiation(ctx context.Context, c net.Conn) error {
	// Read authentication version
	buf := make([]byte, 1)
	if _, err := utils.ReadWithContext(ctx, c, buf); err != nil {
		return errors.Join(proxy_error.ErrSocks5UnableToReadUserPassAuthVersion, err)
	}
	if buf[0] != userPassAuthVersion {
		return errors.Join(proxy_error.ErrSocks5UnsupportedUserPassAuthVersion, fmt.Errorf("sent version: %d", buf[0]))
	}

	// Read username
	if _, err := utils.ReadWithContext(ctx, c, buf); err != nil {
		return errors.Join(proxy_error.ErrSocks5UnableToReadUserPassAuthUsernameLength, err)
	}
	ulen := buf[0]
	uname := make([]byte, ulen)
	if _, err := utils.ReadWithContext(ctx, c, uname); err != nil {
		return errors.Join(proxy_error.ErrSocks5UnableToReadUserPassAuthUsername, err)
	}

	// Read password
	if _, err := utils.ReadWithContext(ctx, c, buf); err != nil {
		return errors.Join(proxy_error.ErrSocks5UnableToReadUserPassAuthPasswordLength, err)
	}
	plen := buf[0]
	pass := make([]byte, plen)
	if _, err := utils.ReadWithContext(ctx, c, pass); err != nil {
		return errors.Join(proxy_error.ErrSocks5UnableToReadUserPassAuthPassword, err)
	}

	authOk := true

	// TODO: Implement actual authentication logic here

	if !authOk {
		if err := sendTwoBytesResponse(c, userPassAuthVersion, userPassAuthFailed); err != nil {
			return errors.Join(proxy_error.ErrSocks5UnableToSendUserPassAuthFailedResponse, err)
		}
	} else {
		if err := sendTwoBytesResponse(c, userPassAuthVersion, userPassAuthSuccess); err != nil {
			return errors.Join(proxy_error.ErrSocks5UnableToSendUserPassAuthSuccessResponse, err)
		}
	}

	return nil
}

// sendTwoBytesResponse sends a two-byte response to the client
func sendTwoBytesResponse(c net.Conn, version, method byte) error {
	if _, err := c.Write([]byte{version, method}); err != nil {
		return errors.Join(proxy_error.ErrSocks5UnableToSendVersionResponse, err)
	}
	return nil
}

// handleSocks5Request processes the SOCKS5 request from the client
// It reads the requested address type, address, and port
func handleSocks5Request(ctx context.Context, c net.Conn) (byte, string, error) {
	// Read version, command, and reserved byte
	buf := make([]byte, 3)
	if _, err := utils.ReadWithContext(ctx, c, buf); err != nil {
		return 0, "", errors.Join(proxy_error.ErrSocks5UnableToReadRequest, err)
	}
	if buf[0] != socks5Version || buf[1] != 1 {
		return 0, "", errors.Join(proxy_error.ErrSocks5UnsupportedVersionOrCommand, fmt.Errorf("unsupported socks request:\nVersion: %d\nCommand: %d", buf[0], buf[1]))
	}

	// Read address type
	if _, err := utils.ReadWithContext(ctx, c, buf[:1]); err != nil {
		return 0, "", errors.Join(proxy_error.ErrSocks5UnableToReadAddressType, err)
	}

	atyp := buf[0]
	taddr, err := readAddress(ctx, c, atyp)
	if err != nil {
		return 0, "", err
	}

	tport, err := readPort(ctx, c)
	if err != nil {
		return 0, "", err
	}

	fullTargetAddr := net.JoinHostPort(taddr, fmt.Sprint(tport))
	return atyp, fullTargetAddr, nil
}

// readAddress reads the address based on the address type
func readAddress(ctx context.Context, c net.Conn, atyp byte) (string, error) {
	var taddr string
	var buf []byte

	switch atyp {
	case AtypIPv4:
		buf = make([]byte, net.IPv4len)
		if _, err := utils.ReadWithContext(ctx, c, buf); err != nil {
			return "", errors.Join(proxy_error.ErrSocks5UnableToReadIpv4, err)
		}
		taddr = net.IP(buf).String()
	case AtypIPv6:
		buf = make([]byte, net.IPv6len)
		if _, err := utils.ReadWithContext(ctx, c, buf); err != nil {
			return "", errors.Join(proxy_error.ErrSocks5UnableToReadIpv6, err)
		}
		taddr = net.IP(buf).String()
	case AtypDomain:
		buf = make([]byte, 1)
		if _, err := utils.ReadWithContext(ctx, c, buf); err != nil {
			return "", errors.Join(proxy_error.ErrSocks5UnableToReadDomain, err)
		}
		domainLen := buf[0]
		buf = make([]byte, domainLen)
		if _, err := utils.ReadWithContext(ctx, c, buf); err != nil {
			return "", errors.Join(proxy_error.ErrSocks5UnableToReadDomain, err)
		}
		taddr = string(buf)
	default:
		return "", errors.Join(proxy_error.ErrSocks5UnsupportedAddressType, fmt.Errorf("sent address type: %d", atyp))
	}

	return taddr, nil
}

// readPort reads the port number from the connection
func readPort(ctx context.Context, c net.Conn) (uint16, error) {
	buf := make([]byte, 2)
	if _, err := utils.ReadWithContext(ctx, c, buf); err != nil {
		return 0, errors.Join(proxy_error.ErrSocks5UnableToReadPort, err)
	}
	return binary.BigEndian.Uint16(buf), nil
}

// sendSocks5SuccessResponse sends a success response to the client
func sendSocks5SuccessResponse(c net.Conn) error {
	res := []byte{socks5Version, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	if _, err := c.Write(res); err != nil {
		return errors.Join(proxy_error.ErrSocks5UnableToSendSuccessResponse, err)
	}
	return nil
}
