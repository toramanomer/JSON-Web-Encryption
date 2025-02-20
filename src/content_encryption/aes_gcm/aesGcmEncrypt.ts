import type { KeyObject } from 'node:crypto'
import { createCipheriv } from 'node:crypto'
import { Buffer } from 'node:buffer'
import { isKeyObject } from 'node:util/types'
import { isBuffer } from '../../common/utils/isBuffer.js'
import { gcmParams } from '../../common/constants/enc.js'

type AesGcmEncryptInput = {
	/**
	 * The AEAD algorithm to use depending on **enc** Header Parameter value.
	 *
	 * Must be one of:
	 * - `'aes-128-gcm'` (when `enc` is `A128GCM`)
	 * - `'aes-192-gcm'` (when `enc` is `A192GCM`)
	 * - `'aes-256-gcm'` (when `enc` is `A256GCM`)
	 */
	aesAlg: keyof typeof gcmParams

	plaintext: Buffer

	/**
	 * **Cipher Key**
	 *
	 * This corresponds to the **Content Encryption Key (CEK)**
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
	 * **Initialization Vector (IV)**
	 *
	 * - The size of the IV must be 12 bytes (96 bits)
	 */
	iv: Buffer

	/**
	 * Additional Authenticated Data
	 */
	aad: Buffer
}

export const aesGcmEncrypt = ({
	aesAlg,
	plaintext,
	cipherKey,
	iv,
	aad
}: AesGcmEncryptInput) => {
	// Validate Alg
	if (!gcmParams[aesAlg])
		throw new TypeError(`Unsupported algorithm: ${aesAlg}`)

	const { cekBytes, ivBytes, authTagBytes } = gcmParams[aesAlg]

	// Validate plaintext
	if (!isBuffer(plaintext)) throw new TypeError('plaintext must be a Buffer.')

	// Validate Cipher Key
	if (!isKeyObject(cipherKey))
		throw new TypeError('cipherKey must be a KeyObject.')
	if (cipherKey.type !== 'secret')
		throw new TypeError('cipherKey must be a symmetric key.')
	if (cipherKey.symmetricKeySize !== cekBytes)
		throw new RangeError(
			`Invalid key length for ${aesAlg}: expected ${cekBytes} bytes.`
		)

	// Validate IV
	if (!isBuffer(iv)) throw new TypeError('iv must be a Buffer.')
	if (iv.length !== ivBytes)
		throw new RangeError(
			`iv must be ${ivBytes} bytes (${ivBytes * 8} bits).`
		)

	// Validate aad
	if (!isBuffer(aad)) throw new TypeError('aad must be a Buffer.')

	const cipher = createCipheriv(aesAlg, cipherKey, iv, {
		authTagLength: authTagBytes
	}).setAAD(aad, { plaintextLength: plaintext.length })

	const jweCiphertext = Buffer.concat([
		cipher.update(plaintext),
		cipher.final()
	])

	return { jweCiphertext, jweAuthenticationTag: cipher.getAuthTag() }
}
