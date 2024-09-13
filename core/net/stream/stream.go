// Package stream provides encrypted network communication using AEAD ciphers.
package stream

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
)

const (
	// packetMessageSize is the maximum bytes for storing the length of a message.
	packetMessageSize = 2
)

// CipherStream wraps a net.Conn and encrypts/decrypts using an AEAD cipher.
type CipherStream struct {
	net.Conn             // Underlying TCP connection
	aead     cipher.AEAD // AEAD cipher for encryption/decryption
	buffer   []byte      // Buffer for reading/writing
}

// Read reads from the underlying connection, decrypting the data.
func (c *CipherStream) Read(b []byte) (int, error) {
	// Check if there's data in the buffer, if so, return it
	if len(c.buffer) > 0 {
		n := copy(b, c.buffer)
		c.buffer = c.buffer[n:]
		return n, nil
	}

	// Read packet length
	encryptedMessageLen := make([]byte, packetMessageSize)
	if _, err := io.ReadFull(c.Conn, encryptedMessageLen); err != nil {
		return 0, err
	}
	encryptedMessageLenInt := binary.BigEndian.Uint16(encryptedMessageLen)

	// Read encryptedMessage (nonce + encryptedMessage)
	encryptedMessage := make([]byte, encryptedMessageLenInt)
	if _, err := io.ReadFull(c.Conn, encryptedMessage); err != nil {
		return 0, err
	}

	// Read nonce first
	nonce := encryptedMessage[:c.aead.NonceSize()]

	//  Read ciphertext
	ciphertext := encryptedMessage[c.aead.NonceSize():]

	// Decrypt the message
	plaintext, err := c.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return 0, err
	}

	// Copy the decrypted data to the buffer
	c.buffer = plaintext

	n := copy(b, c.buffer)
	c.buffer = c.buffer[n:]

	return n, nil
}

// Write encrypts the data and writes to the underlying connection.
func (c *CipherStream) Write(b []byte) (int, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return 0, err
	}

	// Encrypt the message
	ciphertext := c.aead.Seal(nil, nonce, b, nil)

	// Packet is nonce + ciphertext
	packet := append(nonce, ciphertext...)

	// Send message length first
	packetLen := make([]byte, packetMessageSize)
	binary.BigEndian.PutUint16(packetLen, uint16(len(packet)))

	// Write the length-prefixed packet
	if _, err := c.Conn.Write(packetLen); err != nil {
		return 0, err
	}
	_, err := c.Conn.Write(packet)
	if err != nil {
		return 0, err
	}

	return len(b), nil // Return length of the plaintext
}

// NewCipherStream creates a new CipherStream with AEAD encryption.
func NewCipherStream(conn net.Conn, aead cipher.AEAD) *CipherStream {
	return &CipherStream{
		Conn: conn,
		aead: aead,
	}
}
