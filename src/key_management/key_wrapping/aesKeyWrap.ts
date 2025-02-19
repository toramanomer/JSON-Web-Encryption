import { Buffer } from 'node:buffer'
import { isKeyObject } from 'node:util/types'
import { createCipheriv } from 'node:crypto'
import type { KeyObject } from 'node:crypto'

const aesAlgs = {
	'aes128-wrap': 'aes128-wrap',
	'aes192-wrap': 'aes192-wrap',
	'aes256-wrap': 'aes256-wrap'
} as const

type AesKeyWrapInput = {
	/**
	 * The AES key wrapping algorithm to use.
	 *
	 * Must be one of the following:
	 * - `'aes128-wrap'` (for A128KW)
	 * - `'aes192-wrap'` (for A192KW)
	 * - `'aes256-wrap'` (for A256KW)
	 */
	aesAlg: keyof typeof aesAlgs

	/**
	 * **Key Data**
	 *
	 * This corresponds to the **Content Encryption Key (CEK)** that is to be wrapped.
	 *
	 * - The key length must a multiple of 8 bytes.
	 * - The key length must be at least 16 bytes.
	 */
	keyData: Buffer

	/**
	 * **Key-Encryption Key (KEK)**
	 *
	 * - The key used to do the wrapping.
	 * - It must be a symmetric key.
	 *
	 * The size of this key depends on the `aesAlg`:
	 * - `'aes128-wrap'` → **16 bytes (128 bits)**
	 * - `'aes192-wrap'` → **24 bytes (192 bits)**
	 * - `'aes256-wrap'` → **32 bytes (256 bits)**
	 */
	keyEncryptionKey: KeyObject
}

/**
 * Wraps the **Content Encryption Key (CEK)** to produce the **JWE Encrypted Key**
 * using AES Key Wrap when the **alg** header is one of:
 * - `A128KW`
 * - `A192KW`
 * - `A256KW`
 */
export const aesKeyWrap = ({
	aesAlg,
	keyData,
	keyEncryptionKey
}: AesKeyWrapInput) => {
	if (keyData.length % 8 !== 0)
		throw new RangeError('Key Data length must a multiple of 8 bytes.')
	if (keyData.length === 8)
		throw new RangeError('Key Data must be at least 16 bytes.')

	if (!aesAlgs[aesAlg]) throw new TypeError('The algorithm is not supported.')

	if (!isKeyObject(keyEncryptionKey))
		throw new TypeError('KEK is not a KeyObject.')
	if (keyEncryptionKey.type !== 'secret')
		throw new TypeError('KEK is not a symmetric key.')

	const iv = Buffer.alloc(8, 0xa6)
	const cipher = createCipheriv(aesAlg, keyEncryptionKey, iv)

	return {
		jweEncryptedKey: Buffer.concat([cipher.update(keyData), cipher.final()])
	}
}
