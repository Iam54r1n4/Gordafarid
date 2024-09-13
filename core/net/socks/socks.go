// Package socks implements the SOCKS5 proxy protocol.
package socks

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"

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
)

// HandshakeChan is used to communicate the result of the handshake
type HandshakeChan struct {
	TAddr string // Target address
	ATyp  byte   // Address type
	Err   error  // Error, if any
}

// Handshake performs the SOCKS5 handshake process
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
