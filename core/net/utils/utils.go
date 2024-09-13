package utils

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"

	"github.com/Iam54r1n4/Gordafrid/internal/proxy_error"
)

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

func DataTransfering(wg *sync.WaitGroup, errChan chan error, left net.Conn, right net.Conn) {
	defer wg.Done()
	if _, err := io.Copy(left, right); err != nil {
		errChan <- errors.Join(proxy_error.ErrTransferError, err)
		return
	}
}
