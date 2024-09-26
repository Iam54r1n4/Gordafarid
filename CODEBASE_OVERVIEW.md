### Codebase Overview    

- cmd/client/: Entry point for the Client application
    - cmd/client/config.toml: the Client configuration file
- cmd/server/: Entry point for the Server application
    - cmd/server/config.toml: the Server configuration file

- internal/server/: The server logic
    - Implements the server functionality

- internal/client/: The client logic
    - Implements the client functionality

- internal/flags: Command-line flags parsing
    - Manages command-line flags for application
    
- internal/config/: Configuration management
    - Handles configuration management for both client and server
    - Loads and parses configuration files

- internal/logger/: Logging
    - Provides structured logging capabilities for the application


- internal/shared_error/: Shared error handling
    - Defines common error types used across the application


- pkg/net/protocol/socks/: SOCKS5 server-side protocol implementation
    - Implements the SOCKS5 protocol for server-side operations
    - Handles SOCKS5 handshake, authentication, and connection requests
    - Defines structures for various SOCKS5 headers and messages


- pkg/net/protocol/gordafarid/: The Gordafarid protocol implementation
    - Handles handshake process and authentication for Gordafarid connections
    - Manages encrypted connections using AEAD ciphers

- pkg/net/protocol/gordafarid/cipher_conn: The AEAD cipher connection implementation
    - Provides encrypted connection using the AEAD cipher

- pkg/net/protocol/gordafarid/crypto/aead/: Provides AEAD cryptographic functionalities
    - Provides functions for creating and validating passwords

- pkg/net/protocol/gordafarid/crypto/aes_gcm/: AES/GCM cryptographic functionalities
    - Provides encryption and decryption functions using AES-GCM.

- pkg/net/protocol/gordafarid/nonce_cache/: Cryptographic nonce functionalities
    - Provides a mechanism for managing nonce storage and checking for replay attacks
    - Stores nonces with timestamps and allows for expiration of old nonces to prevent memory exhaustion