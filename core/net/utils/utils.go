package utils

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"

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

// DataTransfering transfers data between two network connections.
// It uses io.Copy to efficiently copy data from the right connection to the left connection.
//
// Parameters:
//   - wg: A pointer to a sync.WaitGroup, used to signal when the function has completed.
//   - errChan: A channel to send any errors that occur during the data transfer.
//   - left: The destination net.Conn where data will be written.
//   - right: The source net.Conn from which data will be read.
//
// The function will decrement the WaitGroup counter when it completes.
// If an error occurs during the data transfer, it will be sent to the errChan
// wrapped with the proxy_error.ErrTransferError.
func DataTransfering(wg *sync.WaitGroup, errChan chan error, left net.Conn, right net.Conn) {
	defer wg.Done()
	if _, err := io.Copy(left, right); err != nil {
		errChan <- errors.Join(proxy_error.ErrTransferError, err)
		return
	}
}
