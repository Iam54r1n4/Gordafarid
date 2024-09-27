package utils

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/Iam54r1n4/Gordafarid/pkg/net/protocol"
)

// ReadWithContext reads data from a net.Conn with context support.
// It allows for cancellation and timeout handling using the provided context.
//
// Parameters:
//   - ctx: The context for cancellation and timeout control.
//   - r: An io.Reader to read from, usually a net.Conn.
//   - buf: The buffer to read data into.
//
// Returns:
//   - int: The number of bytes read.
//   - error: Any error that occurred during the read operation or context cancellation.
func ReadWithContext(ctx context.Context, r io.Reader, buf []byte) (int, error) {
	readChan := make(chan struct {
		n   int
		err error
	})

	go func() {
		defer close(readChan)
		n, err := r.Read(buf)
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

// WriteWithContext writes data to a net.Conn with context support.
// It allows for cancellation and timeout handling using the provided context.
//
// Parameters:
//   - ctx: The context for cancellation and timeout control.
//   - w: A writer to write to, usually a net.Conn.
//   - buf: The buffer containing data to write.
//
// Returns:
//   - int: The number of bytes written.
//   - error: Any error that occurred during the write operation or context cancellation.
func WriteWithContext(ctx context.Context, w io.Writer, buf []byte) (int, error) {
	writeChan := make(chan struct {
		n   int
		err error
	})

	go func() {
		defer close(writeChan)
		n, err := w.Write(buf)
		writeChan <- struct {
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
	case v := <-writeChan:
		return v.n, v.err
	}
}

// ReadAddress reads the address based on the address type
func ReadAddress(ctx context.Context, conn net.Conn, atyp byte) ([]byte, error) {
	var buf []byte

	switch atyp {
	case protocol.AtypIPv4:
		buf = make([]byte, net.IPv4len)
		if _, err := ReadWithContext(ctx, conn, buf); err != nil {
			return nil, errors.Join(errUnableToReadIpv4, err)
		}
	case protocol.AtypIPv6:
		buf = make([]byte, net.IPv6len)
		if _, err := ReadWithContext(ctx, conn, buf); err != nil {
			return nil, errors.Join(errUnableToReadIpv6, err)
		}
	case protocol.AtypDomain:
		buf = make([]byte, 1)
		if _, err := ReadWithContext(ctx, conn, buf); err != nil {
			return nil, errors.Join(errUnableToReadDomain, err)
		}
		domainLen := buf[0]
		buf = make([]byte, domainLen)
		if _, err := ReadWithContext(ctx, conn, buf); err != nil {
			return nil, errors.Join(errUnableToReadDomain, err)
		}
	default:
		return nil, errors.Join(errUnsupportedAddressType, fmt.Errorf("sent address type: %d", atyp))
	}
	return buf, nil
}

// ReadPort reads the port number from the connection
func ReadPort(ctx context.Context, conn net.Conn) ([2]byte, error) {
	var port [2]byte
	if _, err := ReadWithContext(ctx, conn, port[:]); err != nil {
		return [2]byte{}, errors.Join(errUnableToReadPort, err)
	}
	return port, nil
}

// IPBytesToString converts IP bytes to a string based on the address type
func IPBytesToString(atyp byte, ip []byte) string {
	switch atyp {
	case protocol.AtypIPv4, protocol.AtypIPv6:
		return net.IP(ip).String()
	case protocol.AtypDomain:
		return string(ip)
	default:
		return ""
	}
}
