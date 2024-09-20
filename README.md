# Gordafarid

Gordafarid is a simple encrypted proxy server/client implementation in Go. Designed primarily for educational purposes, this project demonstrates how to build a basic proxy system with end-to-end encryption, leveraging AEAD ciphers for secure communication.

## Technical Overview

- #### Key Points
   - Data transfer: SOCKS5 over TCP with AEAD encryption for secure communication
   - SOCKS5: Implemented SOCKS5 handshake process
   - SOCKS5: Implemented SOCKS5 Username/Password authentication process
   - Asynchronous I/O : Efficient, non-blocking operations
   - Configurable: Easily customizable with TOML configuration files

- ### Protocol Specification
   - Please read [GORDAFARID_SPECIFICATION.md](https://github.com/Iam54r1n4/Gordafarid/blob/main/GORDAFARID_SPECIFICATION.MD)
   - Also, the code has been written in a way that you can easily understand the concepts. Believe me, there are lots of comments to help you understand the code

- ###  Codebase Overview
   - The main components of the project are:
      - Client code entry point (cmd/client/main.go)
      - Server code entry point(cmd/server/main.go)

### Encryption
- Uses ChaCha20-Poly1305/AES-256-GCM/AES-192-GCM/AES-128-GCM cryptography algorithms for secure communication, based on configs in the config file (config.toml)


## Security Considerations
- Basic authentication mechanism implemented using a pre-shared key shared between the client and the server
- SOCKS5 Username/Password authentication implemented on the client side

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

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Disclaimer

This project is for educational purposes only and should not be used in production environments without significant security enhancements and thorough testing.
