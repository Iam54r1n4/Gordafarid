// Package crypto provides encryption and decryption functions using AES-GCM.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"sync"
	"time"
)

// AES_GCM_NonceSize is the size of the nonce used in AES-GCM encryption.
// It is set to 12 bytes as recommended for AES-GCM.
const AES_GCM_NonceSize = 12

// AES_GCM_AuthTagSize is the size of the authentication tag in AES-GCM.
// It is set to 16 bytes, which provides strong integrity protection.
const AES_GCM_AuthTagSize = 16

var (
	// nonceStorage is a thread-safe map used to store nonces to prevent reuse.
	nonceStorage = sync.Map{}

	// cleanupInterval is the duration between nonce cleanup operations.
	cleanupInterval = time.Minute * 10

	// nonceExpiryTime is the duration after which a nonce is considered expired.
	nonceExpiryTime = time.Minute * 60
)

// init starts a goroutine that periodically cleans up old nonces.
func init() {
	go func() {
		ticker := time.NewTicker(cleanupInterval)
		defer ticker.Stop()
		for range ticker.C {
			cleanupOldNonces()
		}
	}()
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
		if !existsNonce(nonce) {
			// Store the new nonce
			storeNonce(nonce)
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
	if existsNonce(nonce) {
		return nil, ErrDuplicatedNonceUsed
	}
	// Store the new nonce
	storeNonce(nonce)

	// Decrypt and verify the ciphertext
	plaintext, err := gcm.Open(nil, []byte(nonce), []byte(ciphertext), nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// storeNonce stores a nonce in the nonceStorage map with the current timestamp.
func storeNonce(nonce []byte) {
	nonceStorage.Store(string(nonce), time.Now().Unix())
}

// existsNonce checks if a nonce exists in the nonceStorage map.
func existsNonce(nonce []byte) bool {
	_, ok := nonceStorage.Load(string(nonce))
	return ok
}

// cleanupOldNonces removes expired nonces from the nonceStorage map.
func cleanupOldNonces() {
	nowTimestamp := time.Now().Unix()
	nonceStorage.Range(func(key, value any) bool {
		nonceTimestamp := value.(int64)
		nonceExpirySeconds := int64(nonceExpiryTime.Seconds())
		if (nowTimestamp - nonceTimestamp) > nonceExpirySeconds {
			nonceStorage.Delete(key) // Delete expired nonce
		}
		return true
	})
}
