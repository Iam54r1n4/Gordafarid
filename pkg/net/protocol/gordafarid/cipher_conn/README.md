### Cipher Connection
- The `cipher_conn` package provides encrypted connection using the AEAD cipher.
- The Gordafarid protocol uses this package for communication after the client's `Initial Greeting`.

- ### Encrypted Packet Schema:
    
    | Field       | Packet Length  | Nonce                      | Encrypted Message |
    |-------------|----------------|----------------------------|-------------------|
    | Size(Byte)  |  2             | Variable(AEAD Nonce Size)  | Variable          |

    - Packet Length: Indicates the total length of the following data (Nonce + Encrypted Message).
    - Nonce: A unique value for each message to ensure security
    - Encrypted Message: The actual message content, encrypted using the AEAD cipher.
        > NOTICE: The `Encrypted Messge` could be the Gordafarid protocol handshake packet during the handshake process or the actual application data.

