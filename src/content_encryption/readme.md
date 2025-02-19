# Content Encryption

## Content Encryption with AES-GCM (A128GCM, A192GCM, A256GCM)

Authenticated Encryption with AES in Galois/Counter Mode (GCM) is applied when the `enc` (encryption algorithm) header parameter is set to one of the following values:

- `A128GCM`
- `A192GCM`
- `A256GCM`

| `enc` Header Param | Content Encryption Key (CEK)    | Initialization Vector (IV) | Authentication Tag    |
| ------------------ | ------------------------------- | -------------------------- | --------------------- |
| `A128GCM`          | 16-byte (128-bit) symmetric key | 12-byte (96-bit) IV        | 16-byte (128-bit) tag |
| `A192GCM`          | 24-byte (192-bit) symmetric key | 12-byte (96-bit) IV        | 16-byte (128-bit) tag |
| `A256GCM`          | 32-byte (256-bit) symmetric key | 12-byte (96-bit) IV        | 16-byte (128-bit) tag |
