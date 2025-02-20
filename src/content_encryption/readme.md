# Content Encryption

## Content Encryption with AES_CBC_HMAC_SHA2 (`A128CBC-HS256`, `A192CBC-HS384`, `A256CBC-HS512`)

- `A128CBC-HS256`
- `A192CBC-HS384`
- `A256CBC-HS512`

| `enc` Header Param Value | Content Encryption Key (CEK)         | Mac Key                 | Enc Key               | Initialization Vector (IV)  | Authentication Tag  | Hash    |
| ------------------------ | ------------------------------------ | ----------------------- | --------------------- | --------------------------- | ------------------- | ------- |
| `A128CBC-HS256`          | 32-bytes (256-bit) key symmetric key | Initial 16-bytes of CEK | Final 16-bytes of CEK | Must be 16 bytes (128 bits) | 16 bytes (128 bits) | SHA-256 |
| `A192CBC-HS384`          | 48-bytes (384-bit) key symmetric key | Initial 24-bytes of CEK | Final 24-bytes of CEK | Must be 16 bytes (128 bits) | 24 bytes (192 bits) | SHA-384 |
| `A256CBC-HS512`          | 64-bytes (512-bit) key symmetric key | Initial 32-bytes of CEK | Final 32-bytes of CEK | Must be 16 bytes (128 bits) | 32 bytes (256 bits) | SHA-512 |

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
