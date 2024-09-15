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
)

func ValidateSocks5(timeoutMilliseconds int, c net.Conn) error {
	// Sample of valid SOCKS5 header in for client proxy:
	//     VER=5
	//     NMETHODS=1
	//     METHODS=0
	// The only valid value in the client proxy for METHODS is 0x00, which indicates that the client(local application) is using "No Authentication"

	headerBuf := make([]byte, 3)
	timeoutCtx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutMilliseconds)*time.Millisecond)
	defer cancel()
	if _, err := utils.ReadWithContext(timeoutCtx, c, headerBuf); err != nil {
		return errors.Join(proxy_error.ErrSocks5UnableToReadVersion, err)
	}
	// Check the request version
	if headerBuf[0] != version {
		return errors.Join(proxy_error.ErrSocks5UnsupportedVersion, fmt.Errorf("sent version: %d", headerBuf[0]))
	}
	// Check the request nMethods field
	if headerBuf[1] != 1 {
		return errors.Join(proxy_error.ErrSocks5InvalidNMethodsValue, fmt.Errorf("sent nmethods: %d", headerBuf[1]))
	}
	if headerBuf[2] != 0 {
		return errors.Join(proxy_error.ErrSocks5InvalidMethod, fmt.Errorf("sent auth method: %d", headerBuf[2]))
	}
	return nil
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

	if err := checkVersion(ctx, c); err != nil {
		hChan <- HandshakeChan{Err: err}
		return
	}

	if err := sendVersionResponse(c); err != nil {
		hChan <- HandshakeChan{Err: err}
		return
	}

	if err := checkRequest(ctx, c); err != nil {
		hChan <- HandshakeChan{Err: err}
		return
	}

	atyp, taddr, err := readAddress(ctx, c)
	if err != nil {
		hChan <- HandshakeChan{Err: err}
		return
	}

	tport, err := readPort(ctx, c)
	if err != nil {
		hChan <- HandshakeChan{Err: err}
		return
	}

	fullTargetAddr := net.JoinHostPort(taddr, fmt.Sprint(tport))

	if err := sendSuccessResponse(c); err != nil {
		hChan <- HandshakeChan{Err: err}
		return
	}

	hChan <- HandshakeChan{TAddr: fullTargetAddr, ATyp: atyp}
}

func checkVersion(ctx context.Context, c net.Conn) error {
	buf := make([]byte, 2)
	if _, err := utils.ReadWithContext(ctx, c, buf); err != nil {
		return errors.Join(proxy_error.ErrSocks5UnableToReadVersion, err)
	}
	if buf[0] != version {
		return errors.Join(proxy_error.ErrSocks5UnsupportedVersion, fmt.Errorf("sent version: %d", buf[0]))
	}
	nMethods := buf[1]
	if _, err := io.CopyN(io.Discard, c, int64(nMethods)); err != nil {
		return errors.Join(proxy_error.ErrSocks5UnableToDiscardNMethods, fmt.Errorf("sent nmethods: %d", nMethods), err)
	}
	return nil
}

func sendVersionResponse(c net.Conn) error {
	if _, err := c.Write([]byte{version, 0}); err != nil {
		return errors.Join(proxy_error.ErrSocks5UnableToSendVersionResponse, err)
	}
	return nil
}

func checkRequest(ctx context.Context, c net.Conn) error {
	buf := make([]byte, 3)
	if _, err := utils.ReadWithContext(ctx, c, buf); err != nil {
		return errors.Join(proxy_error.ErrSocks5UnableToReadRequest, err)
	}
	if buf[0] != version || buf[1] != 1 {
		return errors.Join(proxy_error.ErrSocks5UnsupportedVersionOrCommand, fmt.Errorf("unsupported socks request:\nVersion: %d\nCommand: %d", buf[0], buf[1]))
	}
	return nil
}

func readAddress(ctx context.Context, c net.Conn) (byte, string, error) {
	buf := make([]byte, 1)
	if _, err := utils.ReadWithContext(ctx, c, buf); err != nil {
		return 0, "", errors.Join(proxy_error.ErrSocks5UnableToReadAddressType, err)
	}

	atyp := buf[0]
	var taddr string
	var err error

	switch atyp {
	case AtypIPv4:
		taddr, err = readIPv4(ctx, c)
	case AtypIPv6:
		taddr, err = readIPv6(ctx, c)
	case AtypDomain:
		taddr, err = readDomain(ctx, c)
	default:
		err = errors.Join(proxy_error.ErrSocks5UnsupportedAddressType, fmt.Errorf("sent address type: %d", atyp))
	}

	return atyp, taddr, err
}

func readIPv4(ctx context.Context, c net.Conn) (string, error) {
	buf := make([]byte, net.IPv4len)
	if _, err := utils.ReadWithContext(ctx, c, buf); err != nil {
		return "", errors.Join(proxy_error.ErrSocks5UnableToReadIpv4, err)
	}
	return net.IP(buf).String(), nil
}

func readIPv6(ctx context.Context, c net.Conn) (string, error) {
	buf := make([]byte, net.IPv6len)
	if _, err := utils.ReadWithContext(ctx, c, buf); err != nil {
		return "", errors.Join(proxy_error.ErrSocks5UnableToReadIpv6, err)
	}
	return string(buf), nil
}

func readDomain(ctx context.Context, c net.Conn) (string, error) {
	buf := make([]byte, 1)
	if _, err := utils.ReadWithContext(ctx, c, buf); err != nil {
		return "", errors.Join(proxy_error.ErrSocks5UnableToReadDomain, err)
	}
	domainLen := buf[0]
	buf = make([]byte, domainLen)
	if _, err := utils.ReadWithContext(ctx, c, buf); err != nil {
		return "", errors.Join(proxy_error.ErrSocks5UnableToReadDomain, err)
	}
	return string(buf), nil
}

func readPort(ctx context.Context, c net.Conn) (uint16, error) {
	buf := make([]byte, 2)
	if _, err := utils.ReadWithContext(ctx, c, buf); err != nil {
		return 0, errors.Join(proxy_error.ErrSocks5UnableToReadPort, err)
	}
	return binary.BigEndian.Uint16(buf), nil
}

func sendSuccessResponse(c net.Conn) error {
	res := []byte{version, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	if _, err := c.Write(res); err != nil {
		return errors.Join(proxy_error.ErrSocks5UnableToSendSuccessResponse, err)
	}
	return nil
}
