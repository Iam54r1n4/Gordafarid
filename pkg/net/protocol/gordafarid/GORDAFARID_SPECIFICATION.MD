# Gordaafarid Specification

- #### Handshake Process

    - ##### Client -> Server: `Initial Greeting`:

        | Field       | VER | CMD | HASH |
        |-------------|-----|-----|------|
        | Size(Byte)  |  1  |  1  |  32  |

        - VER: Gordafarid protocol version (0x01 for Gordafarid)
        - CMD: Command (0x01 for CONNECT, 0x02 for BIND, 0x03 for UDP ASSOCIATE)
        - HASH: Hash value used for authentication

    - ##### Server -> Client: `Greeting Response`:

        | Field       | VER | STATUS  |
        |-------------|-----|---------|
        | Size(Byte)  | 1   | 1       |

        - VER: Gordafarid protocol version (0x01 for Gordafarid)
        - STATUS: Status of the handshake (0x00 for success, 0x01 for failure)


        > `NOTICE: After this stage all communication is encrypted.`

    - ##### Client -> Server: `Request`:

        | Field       | ATYP | DST.ADDR | DST.PORT |
        |-------------|------|----------|----------|
        | Size(Byte)  | 1    | Variable | 2        |

        - ATYP: Address type (0x01 for IPv4, 0x03 for domain name, 0x04 for IPv6)
        - DST.ADDR: Destination address
        - DST.PORT: Destination port

    - ##### Server -> Client: `Reply`:

        | Field       | VER | STATUS | ATYP | BND.ADDR | BND.PORT |
        |-------------|-----|--------|------|----------|----------|
        | Size(Byte)  | 1   | 1      | 1    | Variable | 2        |

        - VER: Gordafarid protocol version (0x01 for Gordafarid)
        - STATUS: Status of the handshake (0x00 for success, 0x01 for failure)
        - ATYP: Address type (0x01 for IPv4, 0x03 for domain name, 0x04 for IPv6)
        - BND.ADDR: Bound address
        - BND.PORT: Bound port


- #### Encryption
    - Supports `ChaCha20-Poly1305`/`AES-256-GCM`/`AES-192-GCM`/`AES-128-GCM` cryptography algorithms for secure communication

    - ##### Encrypted Packet:

        | Field      | Message Length | Nonce           | CipherText |
        |------------|----------------|-----------------|------------|
        | Size(Byte) | 2              | AEAD Nonce Size | Variable   |

        - Message Length: Indicates the total length of the following data (Nonce + Encrypted Message)
        - Nonce : A unique value for each message to ensure security
        - Encrypted Message: The actual message content, encrypted using the AEAD cipher




- #### Traffic Flow
    - Data Flow:
        - Local Application ⇄ Client Proxy ⇄ (Encrypted Data) ⇄ Server Proxy ⇄ Target Server

    - Client-Side Flow:
        - Local Application initiates SOCKS5 request to Client proxy
        - Client performs SOCKS5 handshake also the client side authentication by SOCKS5 authentication mechanism itself
        - Client extracts target address from SOCKS5 handshake
        - Client establishes connection to the Proxy Server using Gordafarid protocol
        - Client sends Gordafarid `Initial Greeting` to Proxy Server (performs Client-Server authentication)
        - Client encrypts and sends `Request` to Proxy Server
        - Client receives and decrypts `Reply` from Proxy Server
        - Client begins relaying encrypted data between the Local Application and the Proxy Server

    - Server-Side Flow:
        - Proxy Server receives Gordafarid `Initial Greeting` from Client Proxy
        - Proxy Server sends Gordafarid `Greeting Response`
        - Proxy Server receives and decrypts `Request` from Client Proxy
        - Proxy Server sends encrypted `Reply` to Client Proxy
        - Proxy Server establishes connection to Target Server that was indicated in the handshake process
        - Proxy Server begins relaying encrypted data between Client Proxy and Target Server
