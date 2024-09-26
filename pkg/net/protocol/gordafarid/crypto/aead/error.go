package aead

import "errors"

var (
	errCryptoAlgorithmUnsupported = errors.New("crypto.algorithm is not supported")
	errAccountPasswordInvalid     = errors.New("account.password length is invalid, must sync to selected crypto algorithm key length")
)
