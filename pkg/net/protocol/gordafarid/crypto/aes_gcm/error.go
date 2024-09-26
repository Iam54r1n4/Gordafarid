package aes_gcm

import "errors"

var (
	errCiphertextIsTooShortToDecrypttion = errors.New("ciphertext is too short to decryption")
	ErrDuplicatedNonceUsed               = errors.New("duplicate nonce used for AES/GCM decryption")
)
