# Gordafarid

Gordafarid is a simple encrypted proxy server/client implementation in Go. Designed primarily for educational purposes, this project demonstrates how to build a basic proxy system with end-to-end encryption, leveraging AEAD ciphers for secure communication.

## Technical Overview

- #### Key Points
   - Data transfer: SOCKS5 over TCP with AEAD encryption for secure communication
   - SOCKS5: Implemented SOCKS5 handshake process
   - SOCKS5: Implemented SOCKS5 Username/Password authentication process
   - Asynchronous I/O : Efficient, non-blocking operations
   - Configurable: Easily customizable with TOML configuration files
- #### Packet Structure: [2-byte length prefix] [nonce] [encrypted payload]:
   ```plaintext
   +----------------+--------------------+------------------------+
   | Message Length | Nonce              | Encrypted Message      |
   | (2 bytes)      | (AEAD Nonce Size)  | (Variable Length)      |
   +----------------+--------------------+------------------------+
   
   1. Message Length (2 bytes): Indicates the total length of the following data (Nonce + Encrypted Message)
   2. Nonce (AEAD Nonce Size): A unique value for each message to ensure security
   3. Encrypted Message: The actual message content, encrypted using the AEAD cipher
   ```

- #### Traffic Flow
   - Client-Side flow:
      ```plaintext
      [Local Application] -- SOCKS5 request --> [Client Proxy] -- Validate SOCKS5 header --> AEAD encrypt --> Send encrypted SOCKS5 packet over TCP to Server.
      ```

   - Server-Side flow:
      ```plaintext
      [Server Proxy] -- Receive encrypted SOCKS5 packet --> AEAD decrypt --> Perform SOCKS5 handshake(Parse request) --> Establish connection to Target Server --> Relay/Proxy client data to Target Server
      ```

   - Target-Response flow:
      ```plaintext
      [Target Server] -- Response Data --> [Server Proxy] --> AEAD encrypt --> Send encrypted data back to Client Proxy --> AEAD decrypt --> Forward response to Local Application
      ```
###  Components

0. The main components of the project are:
   - Client code entry point (cmd/client/main.go)
   - Server code entry point(cmd/server/main.go)

1. SOCKS5 Implementation (core/net/socks/socks.go)
   - Handles SOCKS5 handshake process
   - Supports IPv4, IPv6, and domain name address types

2. Encrypted Stream (core/net/stream/stream.go)
   - CipherStream struct wraps net.Conn with AEAD encryption
   - Implements custom Read and Write methods for transparent encryption/decryption

3. Cryptography Functions (core/crypto/crypto.go)
   - Provides AEAD ciphers for encryption and decryption

4. Client Implementation (core/client/client.go)
   - Listens for incoming Socks5 connections
   - Establishes encrypted connections to the remote server
   - Handles bidirectional data transfer

5. Server Implementation (core/server/server.go)
   - Listens for encrypted incoming connections
   - Decrypts the encrypted packets
   - Performs the Socks5 handshake
   - Gets the target server address and port
   - Establishes normal tcp-based connection to the target
   - Handles bidirectional data transfer between target and the client

6. Utility Functions (core/net/utils/utils.go)
   - ReadWithContext: Performs context-aware read operations

7. Configuration Management (core/config/config.go)
   - Handles loading and parsing of configuration files

8. Logging (core/logger/logger.go)
   - Provides structured logging capabilities

### Encryption

- Uses ChaCha20-Poly1305/AES-256-GCM/AES-192-GCM/AES-128-GCM cryptography algorithms for secure communication, based on configs in the config file (config.toml)


## Security Considerations
- Basic authentication mechanism implemented using a pre-shared key

## Usage
0. Clone the repository
```bash
git clone https://github.com/Iam54r1n4/Gordafarid
```

1. Setup the server's config file
```bash
vi Gordafarid/cmd/server/config.toml
```

2. Start the server
```bash
cd Gordafarid/cmd/server/
go run main.go
```


3. Setup the client's config file
```bash
vi Gordafarid/cmd/client/config.toml
```

4. Start the client
```bash
cd Gordafarid/cmd/client/
go run main.go
```

5. Set the proxy to the client.address you defined in the client's config file


### Dependencies

- Go 1.22.2
- golang.org/x/crypto v0.27.0
- golang.org/x/sys v0.25.0
- github.com/BurntSushi/toml v1.4.0
- github.com/sirupsen/logrus v1.9.3

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Disclaimer

This project is for educational purposes only and should not be used in production environments without significant security enhancements and thorough testing.
