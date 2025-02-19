import { createCipheriv } from 'node:crypto'
import type { KeyObject } from 'node:crypto'
import { isKeyObject } from 'node:util/types'
import { isBuffer } from '../../common/utils/isBuffer.js'
import { aesAlgsCekKeyBytes } from '../../common/constants/enc.js'

type AesGcmEncryptInput = {
	/**
	 * The AEAD algorithm to use depending on **enc** Header Parameter value.
	 *
	 * Must be one of:
	 * - `'aes-128-gcm'` (when `enc` is `A128GCM`)
	 * - `'aes-192-gcm'` (when `enc` is `A192GCM`)
	 * - `'aes-256-gcm'` (when `enc``A256GCM`)
	 */
	aesAlg: 'aes-128-gcm' | 'aes-192-gcm' | 'aes-256-gcm'

	plaintext: Buffer

	/**
	 * **Cipher Key**
	 *
	 * This corresponds to the **Content Encryption Key (KEK)**
	 *
	 * - It must be a symmetric (secret) key.
	 *
	 * The required size depends on the `aesAlg`:
	 * - `'aes-128-gcm'` → **16 bytes (128 bits)**
	 * - `'aes-192-gcm'` → **24 bytes (192 bits)**
	 * - `'aes-256-gcm'` → **32 bytes (256 bits)**
	 */
	cipherKey: KeyObject

	/**
	 * **Initialization Vector**
	 *
	 * - The size of the IV must be 8 bytes (96)
	 */
	iv: Buffer

	/**
	 * Additional Authenticated Data
	 */
	aad: Buffer
}

const IV_BYTES = 12
const AUTH_TAG_BYTES = 16

export const aesGcmEncrypt = ({
	aesAlg,
	plaintext,
	cipherKey,
	iv,
	aad
}: AesGcmEncryptInput) => {
	// Validate Alg
	if (!aesAlgsCekKeyBytes[aesAlg]) throw new TypeError('Unsupported alg')

	// Validate plaintext
	if (!isBuffer(plaintext)) throw new TypeError('Plaintext is not a buffer')

	// Validate Cipher Key
	if (!isKeyObject(cipherKey))
		throw new TypeError('Cipher Key is not a KeyObject.')
	if (cipherKey.type !== 'secret')
		throw new TypeError('Cipher Key is not a symmetric key.')
	if (cipherKey.symmetricKeySize !== aesAlgsCekKeyBytes[aesAlg])
		throw new RangeError('Invalid key length for Cipher Key')

	// Validate IV
	if (!isBuffer(iv)) throw new TypeError('IV must be Buffer.')
	if (iv.length !== IV_BYTES)
		throw new RangeError('IV must be 12 bytes (96 bits).')

	// Validate aad
	if (!isBuffer(aad)) throw new TypeError('AAD must be Buffer')

	const cipher = createCipheriv(aesAlg, cipherKey, iv, {
		authTagLength: AUTH_TAG_BYTES
	}).setAAD(aad, { plaintextLength: plaintext.length })

	const jweCiphertext = Buffer.concat([
		cipher.update(plaintext),
		cipher.final()
	])

	return { jweCiphertext, jweAuthenticationTag: cipher.getAuthTag() }
}
