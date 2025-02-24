import { Buffer } from 'node:buffer'
import { createSecretKey, type KeyObject } from 'node:crypto'
import {
	type EncHeaderParameterValues,
	encHeaderParameterValues,
	encHeaderParameters
} from '../common/constants/enc.js'
import { generateAesKey } from '../common/crypto/generateAesKey.js'
import { generateHmacKey } from '../common/crypto/generateHmacKey.js'

/**
 * Generates a Content Encryption Key (CEK) based on the specified encryption algorithm.
 *
 * @param {EncHeaderParameterValues} enc - The "enc" (encryption algorithm) header parameter value.
 * @returns {KeyObject} The generated CEK as a `KeyObject`.
 *
 * @throws {TypeError} If the provided encryption algorithm is not supported.
 */
export const generateRandomCek = (enc: EncHeaderParameterValues): KeyObject => {
	switch (enc) {
		// AES-CBC with HMAC authentication (AES_CBC_HMAC_SHA2)
		case encHeaderParameterValues['A128CBC-HS256']:
		case encHeaderParameterValues['A192CBC-HS384']:
		case encHeaderParameterValues['A256CBC-HS512']: {
			const { encKeyBytes, macKeyBytes } = encHeaderParameters[enc]
			// Concatenate AES key and HMAC key to form CEK
			return createSecretKey(
				Buffer.concat([
					generateAesKey(encKeyBytes).export(),
					generateHmacKey(macKeyBytes).export()
				])
			)
		}

		// AES-GCM (Authenticated Encryption)
		case encHeaderParameterValues['A128GCM']:
		case encHeaderParameterValues['A192GCM']:
		case encHeaderParameterValues['A256GCM']: {
			const { cekBytes } = encHeaderParameters[enc]
			return generateAesKey(cekBytes)
		}

		default:
			throw new TypeError(`Unsupported encryption algorithm: ${enc}`)
	}
}
