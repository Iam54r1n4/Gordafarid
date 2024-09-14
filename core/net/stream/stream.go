// Package stream provides encrypted network communication using AEAD ciphers.
package stream

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
)

// Packet Schema:
// +----------------+--------------------+------------------------+
// | Message Length | Nonce              | Encrypted Message      |
// | (2 bytes)      | (AEAD Nonce Size)  | (Variable Length)      |
// +----------------+--------------------+------------------------+
//
// 1. Message Length (2 bytes): Indicates the total length of the following data (Nonce + Encrypted Message)
// 2. Nonce (AEAD Nonce Size): A unique value for each message to ensure security
// 3. Encrypted Message: The actual message content, encrypted using the AEAD cipher

const (
	// packetMessageSize is the maximum bytes for storing the length of a message.
	// We use 2 bytes, which allows for messages up to 65,535 bytes long.
	packetMessageSize = 2
)

// CipherStream wraps a net.Conn and encrypts/decrypts using an AEAD cipher.
// It's like a secret decoder ring for your network messages!
type CipherStream struct {
	net.Conn             // Underlying TCP connection, like a telephone line
	aead     cipher.AEAD // AEAD cipher for encryption/decryption, our secret code
	buffer   []byte      // Buffer for reading/writing, like a notepad to jot down messages
}

// Read reads from the underlying connection, decrypting the data.
// It's like receiving a secret message and decoding it!
func (c *CipherStream) Read(b []byte) (int, error) {
	// Check if there's data in the buffer, if so, return it
	// This is like checking if we have any leftover decoded message from last time
	if len(c.buffer) > 0 {
		n := copy(b, c.buffer)
		c.buffer = c.buffer[n:]
		return n, nil
	}

	// Read packet length
	// This is like checking how long the incoming secret message is
	encryptedMessageLen := make([]byte, packetMessageSize)
	if _, err := io.ReadFull(c.Conn, encryptedMessageLen); err != nil {
		return 0, err
	}
	encryptedMessageLenInt := binary.BigEndian.Uint16(encryptedMessageLen)

	// Read encryptedMessage (nonce + encryptedMessage)
	// This is like receiving the actual secret message
	encryptedMessage := make([]byte, encryptedMessageLenInt)
	if _, err := io.ReadFull(c.Conn, encryptedMessage); err != nil {
		return 0, err
	}

	// Read nonce first
	// The nonce is like a unique stamp for each message to keep it extra safe
	nonce := encryptedMessage[:c.aead.NonceSize()]

	// Read ciphertext
	// This is the actual encrypted secret message
	ciphertext := encryptedMessage[c.aead.NonceSize():]

	// Decrypt the message
	// This is like using our secret decoder ring to understand the message
	plaintext, err := c.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return 0, err
	}

	// Copy the decrypted data to the buffer
	// This is like writing down the decoded message in our notepad
	c.buffer = plaintext

	n := copy(b, c.buffer)
	c.buffer = c.buffer[n:]

	return n, nil
}

// Write encrypts the data and writes to the underlying connection.
// It's like encoding a secret message and sending it!
func (c *CipherStream) Write(b []byte) (int, error) {
	// Generate a nonce
	// This is like creating a unique stamp for our message
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return 0, err
	}

	// Encrypt the message
	// This is like using our secret encoder ring to make the message unreadable
	ciphertext := c.aead.Seal(nil, nonce, b, nil)

	// Packet is nonce + ciphertext
	// We combine the unique stamp (nonce) with our encoded message
	packet := append(nonce, ciphertext...)

	// Send message length first
	// This is like telling the receiver how long our secret message is
	packetLen := make([]byte, packetMessageSize)
	binary.BigEndian.PutUint16(packetLen, uint16(len(packet)))

	// Write the length-prefixed packet
	// This is like sending the length of our message, then the actual message
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
// It's like setting up a new secret communication channel!
func NewCipherStream(conn net.Conn, aead cipher.AEAD) *CipherStream {
	return &CipherStream{
		Conn: conn,
		aead: aead,
	}
}
