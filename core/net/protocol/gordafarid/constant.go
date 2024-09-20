package gordafarid

import "crypto/sha256"

// Constants used in the Gordafarid protocol
const (
	// gordafaridVersion represents the current version of the Gordafarid protocol.
	gordafaridVersion = 1

	// greetingSuccess indicates a successful greeting in the protocol.
	greetingSuccess = 0

	// greetingFailed indicates a failed greeting in the protocol.
	greetingFailed = 1

	// replySuccess indicates a successful reply in the protocol.
	replySuccess = 0

	// replyFailed indicates a failed reply in the protocol.
	replyFailed = 1

	// HashSize defines the size of the hash used in the greeting header.
	// It is set to the size of SHA-256 hash, which is 32 bytes.
	HashSize = sha256.Size
)
