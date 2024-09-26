# Gordaafarid Specification

- #### Handshake Process

    - ##### Client -> Server: `Initial Greeting`:

        > `IMPORTANT`: The client sends the encrypted `Initial Greeting` using AES/GCM via a pre-shared key (`initPassword` field in the config file) to the server.

        | Field       | VER | CMD | HASH |
        |-------------|-----|-----|------|
        | Size(Byte)  |  1  |  1  |  32  |

        - VER: Gordafarid protocol version (0x01 for Gordafarid)
        - CMD: Command (0x01 for CONNECT, 0x02 for BIND, 0x03 for UDP ASSOCIATE)
        - HASH: Hash value used for authentication

        > `NOTICE`: The HASH field is used for authentication. The server will verify the HASH value to ensure the client's identity. Its value is the hash of the client's account username and password.

        > `NOTICE`: The `Initial Greeting` packet size is 34 bytes as you can see; the AES/GCM nonce size is 12 bytes, and its authentication tag size is 16 bytes, so the server always reads `34 + 12 + 16 = 62` bytes from the connection to capture the AES/GCM packet.
        **This is indeed a fingerprint.**

    - ##### Server -> Client: `Greeting Response`:
        > `IMPORTANT`: The server authenticates the client based on the hash field that the client provides as a user. From this moment, all communications are encrypted using AEAD cipher (`cipher_conn` package). To understand the `cipher_conn` encrypted packet schema, read its [README.md](https://github.com/Iam54r1n4/Gordafarid/blob/main/pkg/net/protocol/gordafarid/cipher_conn/README.md).

        | Field       | VER | STATUS  |
        |-------------|-----|---------|
        | Size(Byte)  | 1   | 1       |

        - VER: Gordafarid protocol version (0x01 for Gordafarid)
        - STATUS: Status of the handshake (0x00 for success, 0x01 for failure)


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
