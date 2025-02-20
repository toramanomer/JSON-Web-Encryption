import type { KeyObject } from 'node:crypto'
import { createHmac, createCipheriv } from 'node:crypto'
import { Buffer } from 'node:buffer'
import { isKeyObject } from 'node:util/types'
import { isBuffer } from '../../common/utils/isBuffer.js'
import { cbcParams } from '../../common/constants/enc.js'

type AesCbcHmacShaEncryptInput = {
	/**
	 * The AEAD algorithm to use depending on **enc** Header Parameter value.
	 *
	 * Must be one of:
	 * - `'aes-128-cbc'` (when `enc` is `A128CBC-HS256`)
	 * - `'aes-192-cbc'` (when `enc` is `A192CBC-HS384`)
	 * - `'aes-256-cbc'` (when `enc` is `A256CBC-HS512`)
	 */
	aesAlg: keyof typeof cbcParams

	plaintext: Buffer

	/**
	 * **Cipher Key**
	 *
	 * This corresponds to the **Content Encryption Key (CEK)**
	 *
	 * - It must be a symmetric (secret) key.
	 *
	 * The required size depends on the `aesAlg`:
	 * - `'aes-128-cbc'` → **32 bytes (256 bits)**
	 * - `'aes-192-cbc'` → **48 bytes (384 bits)**
	 * - `'aes-256-cbc'` → **64 bytes (512 bits)**
	 */
	cipherKey: KeyObject

	/**
	 * **Initialization Vector (IV)**
	 *
	 * - The size of the IV must be 16 bytes (128 bits)
	 */
	iv: Buffer

	/**
	 * Additional Authenticated Data
	 */
	aad: Buffer
}

export const aesCbcHmacShaEncrypt = ({
	aesAlg,
	plaintext,
	cipherKey,
	iv,
	aad
}: AesCbcHmacShaEncryptInput) => {
	// Validate Alg
	if (!cbcParams[aesAlg])
		throw new TypeError(`Unsupported algorithm: ${aesAlg}`)

	const {
		macKeyBytes,
		encKeyBytes,
		hmacHashAlg,
		authTagBytes,
		keyBytes,
		ivBytes
	} = cbcParams[aesAlg]

	// Validate plaintext
	if (!isBuffer(plaintext)) throw new TypeError('plaintext must be a Buffer.')

	// Validate Cipher Key
	if (!isKeyObject(cipherKey))
		throw new TypeError('cipherKey must be a KeyObject.')
	if (cipherKey.type !== 'secret')
		throw new TypeError('cipherKey must be a symmetric key.')
	if (cipherKey.symmetricKeySize !== keyBytes)
		throw new RangeError(
			`Invalid key length for ${aesAlg}: expected ${keyBytes} bytes.`
		)

	// Validate IV
	if (!isBuffer(iv)) throw new TypeError('iv must be a Buffer.')
	if (iv.length !== ivBytes)
		throw new RangeError(
			`iv must be ${ivBytes} bytes (${ivBytes * 8} bits).`
		)

	// Validate aad
	if (!isBuffer(aad)) throw new TypeError('aad must be a Buffer.')

	const key = cipherKey.export(),
		macKey = key.subarray(0, macKeyBytes),
		encKey = key.subarray(encKeyBytes)

	// Sanity check
	if (key.length !== macKey.length + encKey.length)
		throw new Error('Key length must be the sum of macKey and encKey')

	const cipher = createCipheriv(aesAlg, encKey, iv)
	const jweCiphertext = Buffer.concat([
		cipher.update(plaintext),
		cipher.final()
	])

	const hmacInput = Buffer.concat([
		aad,
		iv,
		jweCiphertext,
		Buffer.from((aad.length * 8).toString(16).padStart(16, '0'), 'hex')
	])

	const jweAuthenticationTag = createHmac(hmacHashAlg, macKey)
		.update(hmacInput)
		.digest()
		.subarray(0, authTagBytes)

	return { jweCiphertext, jweAuthenticationTag }
}
