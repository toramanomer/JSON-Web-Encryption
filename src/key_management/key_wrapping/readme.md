# Key Wrapping

## AES Key Wrap (A128KW, A192KW, A256KW)

- **Key Data**:  
  The data being wrapped, regardless of whether it is a key. In the context of JWE, this is the **Content Encryption Key (CEK)**.

    Its length **must be** a multiple of 8 bytes and at least 16 bytes.

- **Key-Encryption Key (KEK)**:  
  A symmetric key used with a key-wrapping algorithm to protect key data.

### Supported Algorithms

| `alg` Header Parameter | Key-Encryption Key (KEK) Requirements |
| ---------------------- | ------------------------------------- |
| `A128KW`               | Symmetric / 16 bytes (128 bits)       |
| `A192KW`               | Symmetric / 24 bytes (192 bits)       |
| `A256KW`               | Symmetric / 32 bytes (256 bits)       |
