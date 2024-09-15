// Package socks implements the SOCKS5 proxy protocol.
package socks

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/Iam54r1n4/Gordafarid/core/net/utils"
	"github.com/Iam54r1n4/Gordafarid/internal/proxy_error"
)

// Constants for SOCKS5 protocol
const (
	// version represents the SOCKS protocol version (SOCKS5)
	version = 5

	// AtypIPv4 represents the address type for IPv4 addresses
	AtypIPv4 = 1

	// AtypIPv6 represents the address type for IPv6 addresses
	AtypIPv6 = 4

	// AtypDomain represents the address type for domain names
	AtypDomain = 3

	// NO ACCEPTABLE METHODS
	NoAcceptableMethods = 0xFF
)

func ValidateSocks5(timeoutMilliseconds int, c net.Conn) error {
	buf := make([]byte, 2)

	validationCtx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutMilliseconds)*time.Millisecond)
	defer cancel()
	if _, err := utils.ReadWithContext(validationCtx, c, buf); err != nil {
		return errors.Join(proxy_error.ErrSocks5UnableToReadVersion, err)
	}
	// Check the request version
	if buf[0] != version {
		return errors.Join(proxy_error.ErrSocks5UnsupportedVersion, fmt.Errorf("sent version: %d", buf[0]))
	}

	// Read the request nMethods field
	if buf[1] == 0 {
		return errors.Join(proxy_error.ErrSocks5InvalidNMethodsValue, fmt.Errorf("sent nmethods: %d", buf[1]))
	}

	// Read the request Methods field
	// NOTICE: At the time there are two supported authentication method:
	//     METHODS=0x00 (no authentication)
	//     METHOD=0x02 (username/password)
	methods := make([]byte, buf[1])
	if _, err := utils.ReadWithContext(validationCtx, c, methods); err != nil {
		return errors.Join(proxy_error.ErrSocks5UnableToDiscardNMethods, fmt.Errorf("sent nmethods: %d", buf[1]), err)
	}
	_, err := selectPreferredSocks5AuthMethod(methods)
	return err
}

// selectPreferredSocks5AuthMethod selects the preferred authentication method for SOCKS5 protocol.
//
// It takes a slice of bytes representing the supported authentication methods
// and returns the preferred method or an error if no acceptable method is found.
//
// The function prioritizes methods in the following order:
// 1. No authentication (method 0)
// 2. Username/password authentication (method 2)
//
// Parameters:
//   - methods: A slice of bytes representing the supported authentication methods.
//
// Returns:
//   - byte: The selected authentication method (0, 2, or NoAcceptableMethods).
//   - error: An error if no acceptable method is found, nil otherwise.
func selectPreferredSocks5AuthMethod(methods []byte) (byte, error) {
	for _, method := range methods {
		// If the method is 0 or 2, the client supports no authentication or username/password authentication
		if method == 0 || method == 2 {
			return method, nil
		}
	}

	return NoAcceptableMethods, errors.Join(proxy_error.ErrSocks5InvalidMethod, fmt.Errorf("sent auth method: %s", methods))
}

// HandshakeChan is used to communicate the result of the handshake
type HandshakeChan struct {
	TAddr string // Target address
	ATyp  byte   // Address type
	Err   error  // Error, if any
}

// Handshake performs the SOCKS5 handshake process
// https://www.ietf.org/rfc/rfc1928.txt

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
func Handshake(ctx context.Context, c net.Conn, hChan chan<- HandshakeChan) {

	defer close(hChan)

	// Read the SOCKS version
	buf := make([]byte, 2)
	if _, err := utils.ReadWithContext(ctx, c, buf); err != nil {
		hChan <- HandshakeChan{Err: errors.Join(proxy_error.ErrSocks5UnableToReadVersion, err)}
		return
	}
	// Return error if the version is not supported
	if buf[0] != version {
		hChan <- HandshakeChan{Err: errors.Join(proxy_error.ErrSocks5UnsupportedVersion, fmt.Errorf("sent version: %d", buf[0]))}
		return
	}

	// Read the number of authentication methods
	nMethods := buf[1]
	// Discard the SOCKS5 authentication methods
	if _, err := io.CopyN(io.Discard, c, int64(nMethods)); err != nil {
		hChan <- HandshakeChan{Err: errors.Join(proxy_error.ErrSocks5UnableToDiscardNMethods, fmt.Errorf("sent nmethods: %d", nMethods), err)}
		return
	}

	// Send the SOCKS5 response (version and no authentication required)
	if _, err := c.Write([]byte{version, 0}); err != nil {
		hChan <- HandshakeChan{Err: errors.Join(proxy_error.ErrSocks5UnableToSendVersionResponse, err)}
		return
	}

	// Read the SOCKS5 request
	buf = make([]byte, 3)
	if _, err := utils.ReadWithContext(ctx, c, buf); err != nil {
		hChan <- HandshakeChan{Err: errors.Join(proxy_error.ErrSocks5UnableToReadRequest, err)}
		return
	}
	if buf[0] != version || buf[1] != 1 {
		hChan <- HandshakeChan{Err: errors.Join(proxy_error.ErrSocks5UnsupportedVersionOrCommand, fmt.Errorf("unsupported socks request:\nVersion: %d\nCommand: %d", buf[0], buf[1]))}
		return
	}

	// Read the address type
	if _, err := utils.ReadWithContext(ctx, c, buf[:1]); err != nil {
		hChan <- HandshakeChan{Err: errors.Join(proxy_error.ErrSocks5UnableToReadAddressType, err)}
		return
	}

	var taddr string
	var atyp byte = buf[0]
	switch atyp {
	case AtypIPv4: // IPv4
		buf = make([]byte, net.IPv4len)
		if _, err := utils.ReadWithContext(ctx, c, buf); err != nil {
			hChan <- HandshakeChan{Err: errors.Join(proxy_error.ErrSocks5UnableToReadIpv4, err)}
			return
		}
		taddr = net.IP(buf).String()
	case AtypIPv6: // IPv6
		buf = make([]byte, net.IPv6len)
		if _, err := utils.ReadWithContext(ctx, c, buf); err != nil {
			hChan <- HandshakeChan{Err: errors.Join(proxy_error.ErrSocks5UnableToReadIpv6, err)}
			return
		}
		taddr = string(buf)
	case AtypDomain: // Domain
		if _, err := utils.ReadWithContext(ctx, c, buf[:1]); err != nil {
			hChan <- HandshakeChan{Err: errors.Join(proxy_error.ErrSocks5UnableToReadDomain, err)}
			return
		}
		buf = make([]byte, buf[0])
		if _, err := utils.ReadWithContext(ctx, c, buf); err != nil {
			hChan <- HandshakeChan{Err: errors.Join(proxy_error.ErrSocks5UnableToReadDomain, err)}
			return
		}
		taddr = string(buf)
	default:
		hChan <- HandshakeChan{Err: errors.Join(proxy_error.ErrSocks5UnsupportedAddressType, fmt.Errorf("sent address type: %d", atyp))}
		return
	}

	// Read the port
	buf = make([]byte, 2)
	if _, err := utils.ReadWithContext(ctx, c, buf); err != nil {
		hChan <- HandshakeChan{Err: errors.Join(proxy_error.ErrSocks5UnableToReadPort, err)}
		return
	}
	var tport uint16 = binary.BigEndian.Uint16(buf)

	// Combine the address and port into a single string
	var fullTargetAddr string = net.JoinHostPort(taddr, fmt.Sprint(tport))

	// Send the SOCKS5 response (success)
	res := []byte{version, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	if _, err := c.Write(res); err != nil {
		hChan <- HandshakeChan{Err: errors.Join(proxy_error.ErrSocks5UnableToSendSuccessResponse, err)}
		return
	}

	// Send the successful handshake result
	hChan <- HandshakeChan{TAddr: fullTargetAddr, ATyp: atyp}
}
