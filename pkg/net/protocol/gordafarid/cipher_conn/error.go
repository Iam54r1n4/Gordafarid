package cipher_conn

import "errors"

var errServerDuplicatedAEADNonceUsedPossibleReplayAttack = errors.New("duplicated nonce used for AEAD ciphers (post-handshake), replay attack is possible")
