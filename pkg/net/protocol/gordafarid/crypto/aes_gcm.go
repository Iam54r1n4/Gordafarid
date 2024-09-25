// Package crypto provides encryption and decryption functions using AES-GCM.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

const (
	// AES_GCM_NonceSize is the size of the nonce used in AES-GCM encryption.
	// It is set to 12 bytes as recommended for AES-GCM.
	AES_GCM_NonceSize = 12
	// AES_GCM_AuthTagSize is the size of the authentication tag in AES-GCM.
	// It is set to 16 bytes, which provides strong integrity protection.
	AES_GCM_AuthTagSize = 16
)

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
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, err
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
		return nil, err
	}

	// Split the nonce and the encrypted data
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Decrypt and verify the ciphertext
	plaintext, err := gcm.Open(nil, []byte(nonce), []byte(ciphertext), nil)

	return plaintext, err
}