import { createEmptyBuffer } from '../../common/utils/createEmptyBuffer.js'

/**
 * Uses the Content Encryption Key (CEK) directly as the shared symmetric key between parties.
 *
 * Since no key wrapping or encryption is performed, the JWE Encrypted Key value is an empty octet sequence.
 *
 * Used when `alg` is `dir`
 */
export const directKeyEncryption = () => ({
	jweEncryptedKey: createEmptyBuffer()
})
