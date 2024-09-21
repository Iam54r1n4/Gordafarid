# Gordafarid

Gordafarid is a simple encrypted proxy server/client implementation in Go. Designed primarily for educational purposes, this project demonstrates how to build a basic proxy system with encryption, leveraging AEAD ciphers for secure communication.

#### Key Points
   - Data transfer: SOCKS5 over TCP with AEAD encryption for secure communication
   - SOCKS5: Implemented SOCKS5 handshake process
   - SOCKS5: Implemented SOCKS5 Username/Password authentication process
   - Asynchronous I/O : Efficient, non-blocking operations
   - Configurable: Easily customizable with TOML configuration files

## Technical Overview

- #### Protocol Specification
   - Please read [GORDAFARID_SPECIFICATION.md](https://github.com/Iam54r1n4/Gordafarid/blob/main/GORDAFARID_SPECIFICATION.MD)
   - Also, the code has been written in a way that you can easily understand the concepts. Believe me, there are lots of comments to help you understand the code

- #### Encryption
   - Uses ChaCha20-Poly1305/AES-256-GCM/AES-192-GCM/AES-128-GCM cryptography algorithms for secure communication, based on configs in the config file (config.toml)

- #### Codebase Overview

   - cmd/client/: Entry point for the Client application
      - cmd/client/config.toml: the Client configuration file
   - cmd/server/: Entry point for the Server application
      - cmd/server/config.toml: the Server configuration file

   - internal/server/: The main server logic
      - Implements the main server functionality
      - Manages incoming connections and handles the Gordafarid protocol
   
   - internal/client/: The main client logic
      - Implements the main client functionality
      - Manages outgoing connections and handles the Gordafarid protocol

   - internal/config/: Configuration management
      - Handles configuration management for both client and server
      - Loads and parses configuration files

   - internal/logger/: Logging
      - Provides structured logging capabilities for the application

   - internal/flags: Command-line flags parsing
      - Manages command-line flags for application

   - internal/shared_error: Shared error handling
      - Defines common error types used across the application


   - pkg/net/protocol/socks: SOCKS5 server-side protocol implementation
      - Implements the SOCKS5 protocol for server-side operations
      - Handles SOCKS5 handshake, authentication, and connection requests
      - Defines structures for various SOCKS5 headers and messages


   - pkg/net/protocol/gordafarid: The Gordafarid protocol implementation
      - Handles handshake process and authentication for Gordafarid connections
      - Manages encrypted connections using AEAD ciphers

   - pkg/net/protocol/gordafarid/cipher: AEAD ciphers implementation
      - Provides implementations of AEAD ciphers for Gordafarid connections


- #### Security Considerations
   - All communication between client and server is encrypted using a pre-shared key shared, except Gordafarid `Initial Greeting`
   - SOCKS5 Username/Password authentication implemented on the client side

## Installation

   - ##### Install from release page:
      - ##### Running the Server
         - Download the appropriate executable from [Releases](https://github.com/Iam54r1n4/Gordafarid/releases) page
         - Set the configuration file for the server
            > The best practice is to put the configuration file in the same directory as the executable, or use the -config flag to specify the path to the configuration file.
         - Run the server

      

      - ##### Running the Client
         - Download the appropriate executable from [Releases](https://github.com/Iam54r1n4/Gordafarid/releases) page
         - Set the configuration file for the client
            > The best practice is to put the configuration file in the same directory as the executable, or use the -config flag to specify the path to the configuration file.
         - Run the client

   - ##### Building from source:
      - ##### Clone the repository
         ```bash
         git clone https://github.com/Iam54r1n4/Gordafarid
         ```

      - ##### Building the Server
         - Navigate to the server directory
            ```bash
            cd Gordafarid/cmd/server/
            ```
         - Set the configuration file for the server
            ```bash
            vi config.toml
            ```
         - Build the server
            ```bash
               go build -o gordafarid-server -v .
            ```
         - Run the server
            ```bash
            ./gordafarid-server -config config.toml
            ```

      - ##### Building the Client
         - Navigate to the client directory
            ```bash
            cd Gordafarid/cmd/client/
            ```
         - Set the configuration file for the client
            ```bash
            vi config.toml
            ```
         - Build the client
            ```bash
            go build -o gordafarid-client -v .
            ```
         - Run the client
            ```bash
            ./gordafarid-client -config config.toml
            ```

### Dependencies

- Go 1.22.2
- golang.org/x/crypto v0.27.0
- golang.org/x/sys v0.25.0
- github.com/BurntSushi/toml v1.4.0

## License

- This project is licensed under the MIT License. See the LICENSE file for details.

## Disclaimer

- This project should not be used in production environments without significant security enhancements and thorough testing.
- I wrote this project in less than two weeks, so it's not perfect.
- [Lyrics](https://github.com/Iam54r1n4/Gordafarid/blob/main/LYRICS.md)