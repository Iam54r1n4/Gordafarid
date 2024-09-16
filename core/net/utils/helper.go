package utils

import (
	"context"
	"net"
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
