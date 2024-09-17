package utils

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/Iam54r1n4/Gordafarid/internal/proxy_error"
)

// ReadWithContext reads data from a net.Conn with context support.
// It allows for cancellation and timeout handling using the provided context.
//
// Parameters:
//   - ctx: The context for cancellation and timeout control.
//   - c: The net.Conn to read from.
//   - buf: The buffer to read data into.
//
// Returns:
//   - int: The number of bytes read.
//   - error: Any error that occurred during the read operation or context cancellation.
func ReadWithContext(ctx context.Context, c net.Conn, buf []byte) (int, error) {
	readChan := make(chan struct {
		n   int
		err error
	})

	go func() {
		defer close(readChan)
		n, err := c.Read(buf)
		readChan <- struct {
			n   int
			err error
		}{
			n:   n,
			err: err,
		}
	}()

	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case v := <-readChan:
		return v.n, v.err
	}
}

// ReadAddress reads the address based on the address type
func ReadAddress(ctx context.Context, conn net.Conn, atyp byte) ([]byte, error) {
	var buf []byte

	switch atyp {
	case AtypIPv4:
		buf = make([]byte, net.IPv4len)
		if _, err := ReadWithContext(ctx, conn, buf); err != nil {
			return nil, errors.Join(proxy_error.ErrSocks5UnableToReadIpv4, err)
		}
	case AtypIPv6:
		buf = make([]byte, net.IPv6len)
		if _, err := ReadWithContext(ctx, conn, buf); err != nil {
			return nil, errors.Join(proxy_error.ErrSocks5UnableToReadIpv6, err)
		}
	case AtypDomain:
		buf = make([]byte, 1)
		if _, err := ReadWithContext(ctx, conn, buf); err != nil {
			return nil, errors.Join(proxy_error.ErrSocks5UnableToReadDomain, err)
		}
		domainLen := buf[0]
		buf = make([]byte, domainLen)
		if _, err := ReadWithContext(ctx, conn, buf); err != nil {
			return nil, errors.Join(proxy_error.ErrSocks5UnableToReadDomain, err)
		}
	default:
		return nil, errors.Join(proxy_error.ErrSocks5UnsupportedAddressType, fmt.Errorf("sent address type: %d", atyp))
	}
	return buf, nil
}

// ReadPort reads the port number from the connection
func ReadPort(ctx context.Context, conn net.Conn) ([2]byte, error) {
	var port [2]byte
	if _, err := ReadWithContext(ctx, conn, port[:]); err != nil {
		return [2]byte{}, errors.Join(proxy_error.ErrSocks5UnableToReadPort, err)
	}
	return port, nil
}
