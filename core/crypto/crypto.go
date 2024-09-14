package crypto

import (
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

var supportedAEADs = []string{
	"chacha20-poly1305",
}

func IsAlgorithmSupported(algoName string) bool {
	algoName = strings.ToLower(algoName)
	for _, supported := range supportedAEADs {
		if algoName == supported {
			return true
		}
	}
	return false
}
func IsKeyLengthFine(algoName string, key []byte) bool {
	if algoName == "chacha20-poly1305" && len(key) == chacha20poly1305.KeySize {
		return true
	}
	return false
}
