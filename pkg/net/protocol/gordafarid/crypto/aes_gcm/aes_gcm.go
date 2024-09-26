// Package aes_gcm provides encryption and decryption functions using AES-GCM.
package aes_gcm

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"time"

	"github.com/Iam54r1n4/Gordafarid/pkg/net/protocol/gordafarid/nonce_cache"
)

// AES_GCM_NonceSize is the size of the nonce used in AES-GCM encryption.
// It is set to 12 bytes as recommended for AES-GCM.
const AES_GCM_NonceSize = 12

// AES_GCM_AuthTagSize is the size of the authentication tag in AES-GCM.
// It is set to 16 bytes, which provides strong integrity protection.
const AES_GCM_AuthTagSize = 16

// NonceCache is a cache of nonces used in AES-GCM encryption to prevent nonce reuse.
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

// Encrypt_AES_GCM encrypts the plaintext using AES-GCM with the provided key.
// It returns the ciphertext (nonce + encrypted data) and any error encountered.
func Encrypt_AES_GCM(plaintext []byte, key []byte) ([]byte, error) {
	// Create a new AES cipher block using the provided key
	aes, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}

	// Wrap the cipher block in Galois Counter Mode
	gcm, err := cipher.NewGCM(aes)
	if err != nil {
		return nil, err
	}

	// Create a nonce (Number used ONCE) with the size required by GCM
	nonce := make([]byte, gcm.NonceSize())
	for {
		// Generate a random nonce
		if _, err := rand.Read(nonce); err != nil {
			return nil, err
		}

		// Check if the nonce has been used before
		if !nonceCache.Exists(nonce) {
			// Store the new nonce
			nonceCache.Store(nonce)
			break
		}
		// If the nonce exists, the loop will continue and generate a new one
	}

	// Encrypt and authenticate the plaintext
	// The nonce is prepended to the ciphertext
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)

	return ciphertext, nil
}

// Decrypt_AES_GCM decrypts the ciphertext using AES-GCM with the provided key.
// It returns the plaintext and any error encountered.
func Decrypt_AES_GCM(ciphertext []byte, key []byte) ([]byte, error) {
	// Create a new AES cipher block using the provided key
	aes, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}

	// Wrap the cipher block in Galois Counter Mode
	gcm, err := cipher.NewGCM(aes)
	if err != nil {
		return nil, err
	}

	// Ensure the ciphertext is long enough to contain a nonce
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errCiphertextIsTooShortToDecrypttion
	}

	// Split the nonce and the encrypted data
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	// Check if the nonce has been used before, if used before replay attack is possible
	if nonceCache.Exists(nonce) {
		return nil, ErrDuplicatedNonceUsed
	}
	// Store the new nonce
	nonceCache.Store(nonce)

	// Decrypt and verify the ciphertext
	plaintext, err := gcm.Open(nil, []byte(nonce), []byte(ciphertext), nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// IsAESPasswordSupported checks if the given password is suitable for AES encryption.
// It returns true if the password length is 16, 24, or 32 bytes (128, 192, or 256 bits),
// which are the supported key sizes for AES.
func IsAESPasswordSupported(password string) bool {
	switch len(password) {
	case 16, 24, 32:
		return true
	default:
		return false
	}
}
