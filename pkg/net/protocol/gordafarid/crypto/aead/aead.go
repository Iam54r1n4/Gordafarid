// Package aead package provides AEAD cryptographic functionality for the Gordafarid project.
package aead

import (
	"crypto/aes"
	"crypto/cipher"

	"golang.org/x/crypto/chacha20poly1305"
)

// aeadConstructor is a function type that creates a new AEAD (Authenticated Encryption with Associated Data) cipher.
type aeadConstructor func([]byte) (cipher.AEAD, error)

// aeadMeta contains metadata for AEAD ciphers.
type aeadMeta struct {
	KeySize     int             // The required key size in bytes
	Constructor aeadConstructor // The function to construct the AEAD cipher
}

// supportedAEADs is a map of supported AEAD ciphers and their metadata.
var supportedAEADs = map[string]aeadMeta{
	"chacha20-poly1305": {KeySize: chacha20poly1305.KeySize, Constructor: chacha20poly1305.New},
	"aes-256-gcm":       {KeySize: 32, Constructor: newAESGCM},
	"aes-192-gcm":       {KeySize: 24, Constructor: newAESGCM},
	"aes-128-gcm":       {KeySize: 16, Constructor: newAESGCM},
}

// newAESGCM creates a new AES-GCM AEAD cipher with the given key.
func newAESGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// IsCryptoSupported checks if the given algorithm and password are supported.
// It returns an error if the algorithm is not supported or if the password length is invalid.
func IsCryptoSupported(algoName, password string) error {
	aeadMeta, ok := supportedAEADs[algoName]
	if !ok {
		return errCryptoAlgorithmUnsupported
	}
	if len(password) != aeadMeta.KeySize {
		return errAccountPasswordInvalid
	}
	return nil
}

// GetAlgorithmKeySize returns the key size in bytes for the given algorithm name.
func GetAlgorithmKeySize(algoName string) (int, error) {
	if err := IsCryptoSupported(algoName, ""); err != nil {
		return 0, err
	}
	aeadMeta := supportedAEADs[algoName]
	return aeadMeta.KeySize, nil
}

// NewAEAD creates a new AEAD cipher based on the given algorithm name and key.
// It returns the AEAD cipher and an error if any occurred during the process.
func NewAEAD(algoName string, key []byte) (cipher.AEAD, error) {
	if err := IsCryptoSupported(algoName, string(key)); err != nil {
		return nil, err
	}

	aeadMeta, ok := supportedAEADs[algoName]
	if !ok {
		return nil, errCryptoAlgorithmUnsupported
	}
	aead, err := aeadMeta.Constructor(key)
	return aead, err
}
