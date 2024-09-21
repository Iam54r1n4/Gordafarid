package utils

import (
	"errors"
	"net"
	"sync"
	"time"
)

var errBufferedConnBufferIsEmpty = errors.New("the BufferedConn internal buffer is empty")

// defaultBufferedConnConnBufferSize is the default buffer size for BufferedConnConn.
const (
	defaultBufferedConnConnBufferSize = 512
	bufferIdleAccessTimeout           = 3 * time.Minute
	bufferIdleChangeTimeout           = 3 * time.Minute
	bufferIdleCheckInterval           = 1 * time.Minute
)

// bufferedConn is a wrapper around net.Conn that allows for re-reading of data.
type bufferedConn struct {
	conn                    net.Conn   // The underlying network connection
	mu                      sync.Mutex // Mutex for thread-safe operations
	buffer                  []byte     // Buffer to store read data
	bufferIndex             int        // Current index in the buffer
	backtrack               bool       // Flag to indicate if we're in backtrack mode
	buffering               bool       // Flag to indicate if buffering is enabled
	bufferLastTimeAccesssed time.Time  // Time of the last access to the buffer
	bufferLastTimeChanged   time.Time  // Time of the last change to the buffer
	bufferIdleLastCheck     time.Time  // Time of the last check for idle buffer
}

// Read reads data from the connection.
// It first checks if there's data in the buffer (when backtracking),
// and if not, it reads from the underlying connection.
func (rr *bufferedConn) Read(p []byte) (int, error) {
	// Clear the buffer if it's been idle for too long
	if time.Since(rr.bufferIdleLastCheck) > bufferIdleCheckInterval {
		if len(rr.buffer) > 0 && time.Since(rr.bufferLastTimeAccesssed) > bufferIdleAccessTimeout && time.Since(rr.bufferLastTimeChanged) > bufferIdleChangeTimeout {
			rr.ResetBuffer()
		}
	}

	rr.mu.Lock()
	defer rr.mu.Unlock()
	// If we're backtracking, read from the buffer
	if rr.backtrack && len(rr.buffer) > 0 {
		// Check if there's any unread data in the buffer
		if len(rr.buffer) > rr.bufferIndex {
			n := copy(p, rr.buffer[rr.bufferIndex:])
			rr.bufferIndex += n
			rr.bufferLastTimeAccesssed = time.Now()
			if rr.bufferIndex >= len(rr.buffer) {
				rr.backtrack = false
			}
			return n, nil
		}
	}

	// Read from the underlying connection
	n, err := rr.conn.Read(p)
	if err != nil {
		return n, err
	}

	// If buffering is enabled, append the read data to the buffer
	if rr.buffering {
		rr.buffer = append(rr.buffer, p[:n]...)
		rr.bufferLastTimeAccesssed = time.Now()
	}
	return n, nil
}

// Backtrack sets the connection to backtrack mode, allowing re-reading of buffered data.
// It panics if buffering is not enabled.
func (rr *bufferedConn) Backtrack() error {
	rr.mu.Lock()
	defer rr.mu.Unlock()
	if !rr.buffering {
		panic("buffering is not enabled")
	}
	if len(rr.buffer) < 1 {
		return errBufferedConnBufferIsEmpty
	}
	rr.backtrack = true
	return nil
}

// StartBuffering enables buffering with the specified size.
// It sets the size value to DefaultBufferedConnConnBufferSize if the size is less than or equal to 0.
func (rr *bufferedConn) StartBuffering(size int) {
	rr.mu.Lock()
	defer rr.mu.Unlock()
	if size <= 0 {
		size = defaultBufferedConnConnBufferSize
	}
	rr.buffer = make([]byte, 0, size)
	rr.buffering = true
	rr.bufferIndex = 0
}

// StopBuffering disables buffering but the current buffer is not cleared and can be reused.
func (rr *bufferedConn) StopBuffering() {
	rr.mu.Lock()
	defer rr.mu.Unlock()
	rr.buffering = false
}

// ResetBuffer clears the buffer and resets the buffer index.
func (rr *bufferedConn) ResetBuffer() {
	rr.buffer = nil
	rr.bufferIndex = 0
}

// NewBufferedConn creates a new BufferedConnConn with the given net.Conn
// and starts buffering with the default buffer size.
func NewBufferedConn(c net.Conn) *bufferedConn {
	r := &bufferedConn{
		conn: c,
	}
	return r
}

// Implement net.Conn interface methods

func (rr *bufferedConn) Write(b []byte) (n int, err error) {
	return rr.conn.Write(b)
}

func (rr *bufferedConn) Close() error {
	return rr.conn.Close()
}

func (rr *bufferedConn) LocalAddr() net.Addr {
	return rr.conn.LocalAddr()
}

func (rr *bufferedConn) RemoteAddr() net.Addr {
	return rr.conn.RemoteAddr()
}

func (rr *bufferedConn) SetDeadline(t time.Time) error {
	return rr.conn.SetDeadline(t)
}

func (rr *bufferedConn) SetReadDeadline(t time.Time) error {
	return rr.conn.SetReadDeadline(t)
}

func (rr *bufferedConn) SetWriteDeadline(t time.Time) error {
	return rr.conn.SetWriteDeadline(t)
}
