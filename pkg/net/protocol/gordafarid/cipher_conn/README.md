### Cipher Connection
- The `cipher_conn` package provides encrypted connections using an AEAD cipher. Supported ciphers are `ChaCha20-Poly1305`, `AES-256-GCM`, `AES-192-GCM`, and `AES-128-GCM`, which can be specified in the config file.
- The Gordafarid protocol uses this package for communication after the client's `Initial Greeting`.

- ### Encrypted Packet Schema:
    
    | Field       | Packet Length  | Nonce                      | Encrypted Message |
    |-------------|----------------|----------------------------|-------------------|
    | Size(Byte)  |  2             | Variable(AEAD Nonce Size)  | Variable          |

    - Packet Length: Indicates the total length of the following data (Nonce + Encrypted Message).
    - Nonce: A unique value for each message to ensure security
    - Encrypted Message: The actual message content, encrypted using the AEAD cipher.
        > NOTICE: The `Encrypted Messge` could be the Gordafarid protocol handshake packet during the handshake process or the actual application data.

