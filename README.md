# Gordafarid

Gordafarid is a simple encrypted proxy server/client implementation in Go, designed for educational purposes to demonstrate how to create a basic proxy system with encryption.

## Technical Overview

### Key Features

- SOCKS5 protocol implementation
- ChaCha20-Poly1305 encryption for secure communication
- Context-aware read operations to do the socks5 handshake
- Asynchronous I/O operations
- TCP-based connections
- Custom packet format: [2-byte length prefix][nonce][encrypted payload]


### Core Components
0. The project consists of two main components:
   - Client (cmd/client/main.go)
   - Server (cmd/server/main.go)

1. SOCKS5 Implementation (core/net/socks/socks.go)
   - Handles SOCKS5 handshake process
   - Supports IPv4, IPv6, and domain name address types

2. Encrypted Stream (core/net/stream/stream.go)
   - CipherStream struct wraps net.Conn with AEAD encryption
   - Implements custom Read and Write methods for transparent encryption/decryption

3. Client Implementation (cmd/client/main.go)
   - Listens for incoming Socks5 connections
   - Establishes encrypted connections to the remote server
   - Handles bidirectional data transfer
4. Server Implementation (cmd/server/main.go)
   - Listens for encrypted incoming connections
   - Descrypts the encrypted packets
   - Performs the Socks5 handshake
   - Gets the target server address and port
   - Establishes normal tcp-based connection to the target
   - Handles bidirectional data transfer between target and the client
5. Utility Functions (core/net/utils/utils.go)
   - ReadWithContext: Performs context-aware read operations

### Encryption

- Uses ChaCha20-Poly1305 AEAD cipher
- 32-byte password for key generation

### Error Handling

- Custom error types defined in internal/proxy_error package
- Extensive use of error wrapping and joining

## Usage
0. Clone the repository

1. Setup the server's config file (cmd/server/config.toml)
2. Start the server
```bash
cd cmd/server/
go run main.go
```

3. Setup the client's config file (cmd/client/config.toml)
4. Start the client
```bash
cd cmd/client/
go run main.go
```
5. Set the proxy to the client.address you defiend in the client's config file

## Security Considerations
- No authentication mechanism implemented in the provided code

### Dependencies

- Go 1.22.2
- golang.org/x/crypto v0.27.0
- golang.org/x/sys v0.25.0
- github.com/BurntSushi/toml v1.4.0

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Disclaimer

This project is for educational purposes only and should not be used in production environments without significant security enhancements and thorough testing.
