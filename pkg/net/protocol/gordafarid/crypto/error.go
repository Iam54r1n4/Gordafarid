package crypto

import "errors"

var (
	errCryptoAlgorithmUnsupported        = errors.New("crypto.algorithm is not supported")
	errAccountPasswordInvalid            = errors.New("account.password length is invalid, must sync to selected crypto algorithm key length")
	ErrDuplicatedNonceUsed               = errors.New("duplicate nonce used for AES/GCM decryption")
	errCiphertextIsTooShortToDecrypttion = errors.New("ciphertext is too short to decryption")
)
