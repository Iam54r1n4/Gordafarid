// The cipher_conn package provides encrypted connection using the AEAD cipher.
package cipher_conn

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"time"

	"github.com/Iam54r1n4/Gordafarid/pkg/net/protocol/gordafarid/nonce_cache"
)

const (
	// packetMessageLengthSize is the maximum bytes for storing the length of a message.
	// We use 2 bytes, which allows for messages up to 65,535 bytes long.
	packetMessageLengthSize = 2
)

// nonceCache is a cache of nonces used in AEAD encryption to prevent nonce reuse.
var nonceCache *nonce_cache.NonceCache

func init() {
	// nonceExpiryTime is the duration after which a nonce is considered expired.
	nonceExpiryTime := time.Minute * 60
	nonceCache = nonce_cache.NewNonceCache(nonceExpiryTime)

	// cleanupInterval is the duration between nonce cleanup operations.
	cleanupInterval := time.Minute * 20
	// Start the cleanup routine in the background that periodically cleans up old nonces.
	nonceCache.StartCleanupRoutine(context.Background(), cleanupInterval)

}

// CipherConn wraps a net.Conn and encrypts/decrypts using an AEAD cipher.
// It's like a secret decoder ring for your network messages!
type CipherConn struct {
	net.Conn             // Underlying TCP connection, like a telephone line
	aead     cipher.AEAD // AEAD cipher for encryption/decryption, our secret code
	buffer   []byte      // Buffer for reading/writing, like a notepad to jot down messages
}

// Read reads from the underlying connection, decrypting the data.
// It's like receiving a secret message and decoding it!
func (c *CipherConn) Read(b []byte) (int, error) {
	// Check if there's data in the buffer, if so, return it
	// This is like checking if we have any leftover decoded message from last time
	if len(c.buffer) > 0 {
		n := copy(b, c.buffer)
		c.buffer = c.buffer[n:]
		return n, nil
	}

	// Read packet length
	// This is like checking how long the incoming secret message is
	encryptedMessageLen := make([]byte, packetMessageLengthSize)
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
	// Check if the nonce has been used before, if used before replay attack is possible
	if nonceCache.Exists(nonce) {
		return 0, errServerDuplicatedAEADNonceUsedPossibleReplayAttack
	}
	// Store the new nonce
	nonceCache.Store(nonce)

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
func (c *CipherConn) Write(b []byte) (int, error) {
	// Generate a nonce
	// This is like creating a unique stamp for our message
	nonce := make([]byte, c.aead.NonceSize())
	for {
		if _, err := rand.Read(nonce); err != nil {
			return 0, err
		}
		// Check if the nonce has been used before, if used before replay attack is possible
		if !nonceCache.Exists(nonce) {
			// Store the new nonce
			nonceCache.Store(nonce)
			break
		}
		// If the nonce exists, the loop will continue and generate a new one
	}

	// Encrypt the message
	// This is like using our secret encoder ring to make the message unreadable
	ciphertext := c.aead.Seal(nil, nonce, b, nil)

	// Packet is nonce + ciphertext
	// We combine the unique stamp (nonce) with our encoded message
	packet := append(nonce, ciphertext...)

	// Send message length first
	// This is like telling the receiver how long our secret message is
	packetLen := make([]byte, packetMessageLengthSize)
	binary.BigEndian.PutUint16(packetLen, uint16(len(packet)))

	fullPacket := append(packetLen, packet...)
	_, err := c.Conn.Write(fullPacket)
	if err != nil {
		return 0, err
	}

	return len(b), nil // Return length of the plaintext
}

func WrapConnToCipherConn(conn net.Conn, aead cipher.AEAD) *CipherConn {
	return &CipherConn{
		Conn: conn,
		aead: aead,
	}
}
