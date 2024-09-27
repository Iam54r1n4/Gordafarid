# Gordafarid

Gordafarid is a simple encrypted proxy server/client implementation in Go. Designed primarily for educational purposes, this project demonstrates how to build a basic proxy system with encryption, leveraging AEAD ciphers for secure communication.

#### Key Points
   - **Educational: Designed as a learning tool to demonstrate proxy server/client implementation with encryption in Go.**
   - Gordafarid Protocol: Implemented a proxy protocol named Gordafarid, inspired by SOCKS5, for secure client-server communication.

   - Secure Communication: All data exchanged between client and server is encrypted. The `Initial Greeting` is encrypted using AES/GCM, and the rest is encrypted using an AEAD cipher.

   - AEAD algorithm support: Supports ChaCha20-Poly1305/AES-256-GCM/AES-192-GCM/AES-128-GCM cryptographic algorithms for secure application data communication(After the `Initial Greeting`).
   
   - Reply attacks: Implements a mechanism to prevent replay attacks by checking for nonce reusage in encrypted communications.

   - User management: Supports multiple users with different credentials, allowing for fine-grained access control.

   - Authentication: Implements SOCKS5 username/password authentication on the client-side for local applications.

   - Flexible Configuration: Easily customizable through TOML configuration files, allowing for versatile deployment scenarios.

   - Code Documentation: the code is well-documented, so you can easily understand the code.

   > - UDP support is not yet implemented. Contributions to add this feature are welcome.
   
   > - Technically speaking, the Gordafarid protocol doesn't disguise itself from DPI, so its traffic detection is not difficult.
   
## Technical Overview

- #### Protocol Specification
   - **Please read [GORDAFARID_SPECIFICATION.md](https://github.com/Iam54r1n4/Gordafarid/blob/main/pkg/net/protocol/gordafarid/GORDAFARID_SPECIFICATION.md)**
   - Also, the code has been written in a way that you can easily understand the concepts, there are lots of comments to help you understand the code.
   
- #### Traffic Flow
    - Overview:
        - Local Application ⇄ Client Proxy ⇄ (Encrypted Data) ⇄ Server Proxy ⇄ Target Server.

    - Client-Side Flow:
        - Local Application initiates SOCKS5 request to Client proxy.
        - Client performs SOCKS5 handshake and authentication using the SOCKS5 authentication mechanism if `socks5Credentials` is not empty.
        - Client extracts target address from SOCKS5 handshake.
        - Client establishes connection to the Proxy Server using Gordafarid protocol.
        - Client sends encrypted Gordafarid `Initial Greeting` to Proxy Server using the AES/GCM algorithm and the pre-shared key specified in the `initPassword` field of the config file.
            > `NOTICE`: After this stage, all communication is encrypted using an AEAD cipher specified in the config file, with its key being the account password.
        - Cilent receives `Greeting Response` from the server and decrypts it.
        - Client encrypts and sends `Request` to Proxy Server.
        - Client receives and decrypts `Reply` from Proxy Server.
        - Client begins relaying encrypted data between the Local Application and the Proxy Server.

    - Server-Side Flow:
        - Proxy Server receives Gordafarid `Initial Greeting` from Client Proxy and decrypts it using AES/GCM algorithm and pre-shared key and specified in the `initPassword` field of the config file.
            > `NOTICE`: After this stage, all communication is encrypted using an AEAD cipher specified in the config file, with its key being the account password.
        - Proxy Server sends encrypted Gordafarid `Greeting Response` to Client Proxy.
        - Proxy Server receives and decrypts `Request` from Client Proxy .
        - Proxy Server sends encrypted `Reply` to Client proxy.
        - Proxy Server establishes connection to Target Server that was indicated in the handshake process.
        - Proxy Server begins relaying encrypted data between Client Proxy and Target Server.


- #### Codebase Overview
    - Please read [CODEBASE_OVERVIEW.md](https://github.com/Iam54r1n4/Gordafarid/blob/main/CODEBASE_OVERVIEW.md)

## Installation

   - ##### Install from release page:
      - ##### Download the appropriate executable
         - [Releases](https://github.com/Iam54r1n4/Gordafarid/releases) page
      - ##### Running the Server
         - Set the configuration file for the server
            > The best practice is to put the configuration file in the same directory as the executable, or use the -config flag to specify the path to the configuration file.
         - Run the server

      

      - ##### Running the Client
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

## Acknowledgements
- Special thanks to [@ReturnFI](https://github.com/ReturnFI) for their valuable assistance.

## Disclaimer

- This project should not be used in production environments without significant security enhancements and thorough testing.
- I wrote this project in less than two weeks, so it's not perfect.
