# Key Manamgent Mode

## Key Encryption

## Key Wrapping

> A Key Management Mode in which the CEK value is encrypted to the intended recipient using a symmetric key wrapping algorithm.

| alg       | Key-Encryption Key (KEK) Requirements | Additional Header Params |
| --------- | ------------------------------------- | ------------------------ |
| A128KW    | Symmetric 16 bytes (128 bits)         |                          |
| A192KW    | Symmetric 24 bytes (192 bits)         |                          |
| A256KW    | Symmetric 32 bytes (256 bits)         |                          |
| A128GCMKW | Symmetric 16 bytes (128 bits)         | "iv", "tag"              |
| A192GCMKW | Symmetric 24 bytes (192 bits)         | "iv", "tag"              |
| A256GCMKW | Symmetric 32 bytes (256 bits)         | "iv", "tag"              |

### AES Key Wrap (A128KW, A192KW, A256KW)

It uses 8-byte long default initial value as A6A6A6A6A6A6A6A6

- **Key Data**:

    The data being wrapped, regardless of whether it is a key. In the context of JWE, this is the **Content Encryption Key (CEK)**.

    Its length **must be** a multiple of 8 bytes and at least 16 bytes.

- **Key-Encryption Key (KEK)**:  
  A symmetric key used with a key-wrapping algorithm to protect key data.

### AES Key Wrap with GCM (A128GCMKW, A192GCMKW, A256GCMKW)

It uses 8-byte long Initialization Vector (IV), and 16-byte long Authentication Tag (Tag).
The IV is represented in the "iv" header parameter, and the Tag is represented in the "tag" header parameter, both encoded as base64url-encoded strings.

- **Key Data**:

    The data being wrapped, regardless of whether it is a key. In the context of JWE, this is the **Content Encryption Key (CEK)**.

    Its length **must be** a multiple of 8 bytes and at least 16 bytes.

- **Key-Encryption Key (KEK)**:

    A symmetric key used with a key-wrapping algorithm to protect key data.

## Direct Key Agreement

## Key Agreement with Key Wrapping

## Direct Encryption
