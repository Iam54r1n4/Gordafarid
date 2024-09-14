# Gordafarid

Gordafarid is a simple encrypted proxy server/client implementation in Go, designed for educational purposes to demonstrate how to create a basic proxy system with encryption.

## Technical Overview

### Architecture

The project consists of two main components:
1. Client (cmd/client/main.go)
2. Server (not shown in the provided context, but implied)

### Key Features

- SOCKS5 protocol implementation
- ChaCha20-Poly1305 encryption for secure communication
- Asynchronous I/O operations
- Context-aware read operations

### Dependencies

- Go 1.22.2
- golang.org/x/crypto v0.27.0
- golang.org/x/sys v0.25.0

### Core Components

1. SOCKS5 Implementation (core/net/socks/socks.go)
   - Handles SOCKS5 handshake process
   - Supports IPv4, IPv6, and domain name address types

2. Encrypted Stream (core/net/stream/stream.go)
   - CipherStream struct wraps net.Conn with AEAD encryption
   - Implements custom Read and Write methods for transparent encryption/decryption

3. Utility Functions (core/net/utils/utils.go)
   - ReadWithContext: Performs context-aware read operations

4. Client Implementation (cmd/client/main.go)
   - Listens for incoming connections
   - Establishes encrypted connections to the remote server
   - Handles bidirectional data transfer

### Encryption

- Uses ChaCha20-Poly1305 AEAD cipher
- 32-byte password for key generation

### Network Communication

- TCP-based connections
- Custom packet format: [2-byte length prefix][nonce][encrypted payload]

### Error Handling

- Custom error types defined in internal/proxy_error package
- Extensive use of error wrapping and joining

## Usage

1. Start the server (implementation not shown in the provided context)
2. Run the client:
3. Configure your application to use the SOCKS5 proxy at 127.0.0.1:8080

## Security Considerations

- Fixed encryption key (password) in the code; should be replaced with secure key management in production
- No authentication mechanism implemented in the provided code

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Disclaimer

This project is for educational purposes only and should not be used in production environments without significant security enhancements and thorough testing.
