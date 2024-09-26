package nonce_cache

import (
	"context"
	"errors"
	"sync"
	"time"
)

// errNonceReuseDetected is returned when a reused nonce is detected (i.e., replay attack).
var errNonceReuseDetected = errors.New("nonce reuse detected")

// NonceCache manages nonce storage and checks for replay attacks.
type NonceCache struct {
	storage    sync.Map      // Nonce storage with timestamps
	expiryTime time.Duration // How long nonces should be kept
}

// NewNonceCache creates a new NonceCache with the specified expiry time for nonces.
func NewNonceCache(expiryTime time.Duration) *NonceCache {
	return &NonceCache{
		expiryTime: expiryTime,
	}
}

// Store stores a nonce in the cache. If the nonce already exists, it returns an error.
func (nc *NonceCache) Store(nonce []byte) error {
	nonceKey := string(nonce) // Store nonce as a string to be used as a key
	if _, exists := nc.storage.Load(nonceKey); exists {
		return errNonceReuseDetected // Nonce has been used before
	}

	// Store the nonce with the current timestamp
	nc.storage.Store(nonceKey, time.Now().Unix())
	return nil
}

// Load loads a nonce from the cache.
func (nc *NonceCache) Load(nonce []byte) (any, bool) {
	nonceKey := string(nonce) // Store nonce as a string to be used as a key
	v, exists := nc.storage.Load(nonceKey)
	return v, exists
}

// Exists checks if a nonce exists in the cache or not
func (nc *NonceCache) Exists(nonce []byte) bool {
	nonceKey := string(nonce) // Store nonce as a string to be used as a key
	_, exists := nc.storage.Load(nonceKey)
	return exists
}

// CleanupExpiredNonces removes nonces that have expired from the cache.
func (nc *NonceCache) CleanupExpiredNonces() {
	nowTimestamp := time.Now().Unix()
	nonceExpirySeconds := int64(nc.expiryTime.Seconds())

	nc.storage.Range(func(key, value any) bool {
		nonceTimestamp := value.(int64)
		// If the nonce is older than the expiry time, delete it
		if (nowTimestamp - nonceTimestamp) > nonceExpirySeconds {
			nc.storage.Delete(key)
		}
		return true
	})
}

// StartCleanupRoutine starts a background routine to periodically clean up expired nonces.
// It runs the cleanup every cleanupInterval, and listens for cancellation via context.
func (nc *NonceCache) StartCleanupRoutine(ctx context.Context, cleanupInterval time.Duration) {
	go func() {
		ticker := time.NewTicker(cleanupInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				nc.CleanupExpiredNonces() // Periodically clean up expired nonces
			case <-ctx.Done():
				// Stop the goroutine when the context is cancelled
				return
			}
		}
	}()
}
