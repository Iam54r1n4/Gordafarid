package utils

import (
	"errors"
	"io"
	"net"
	"sync"
)

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
// wrapped with the errTransfererror.
func DataTransfering(wg *sync.WaitGroup, errChan chan error, left net.Conn, right net.Conn) {
	defer wg.Done()
	if _, err := io.Copy(left, right); err != nil {
		errChan <- errors.Join(errTransfererror, err)
		return
	}
}
