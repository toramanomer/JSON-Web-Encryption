import type { KeyObject } from 'node:crypto'
import {
	encHeaderParameters,
	encHeaderParameterValues,
	type EncHeaderParameterValues
} from '../common/constants/enc.js'

import { aesCbcHmacShaEncrypt } from './aes_cbc_hmac_sha/aesCbcHmacShaEncrypt.js'
import { aesGcmEncrypt } from './aes_gcm/aesGcmEncrypt.js'

type EncryptContentInput = {
	/**
	 * `enc` (encryption algorithm) Header Parameter
	 */
	enc: EncHeaderParameterValues

	/**
	 * Plaintext to encrypt
	 */
	plaintext: Buffer

	/**
	 * Content Encryption Key (CEK)
	 */
	cek: KeyObject

	/**
	 * Initialization Vector (IV)
	 */
	iv: Buffer

	/**
	 * Additional Authenticated Data (AAD)
	 */
	aad: Buffer
}

export const encryptContent = ({
	enc,
	plaintext,
	cek,
	iv,
	aad
}: EncryptContentInput) => {
	switch (enc) {
		// Content Encryption with AES_CBC_HMAC_SHA2
		case encHeaderParameterValues['A128CBC-HS256']:
		case encHeaderParameterValues['A192CBC-HS384']:
		case encHeaderParameterValues['A256CBC-HS512']: {
			const params = encHeaderParameters[enc]
			return aesCbcHmacShaEncrypt({
				aesAlg: params.aesAlg,
				plaintext,
				cipherKey: cek,
				iv,
				aad
			})
		}

		// Content Encryption with AES-GCM
		case encHeaderParameterValues['A128GCM']:
		case encHeaderParameterValues['A192GCM']:
		case encHeaderParameterValues['A256GCM']: {
			const params = encHeaderParameters[enc]
			return aesGcmEncrypt({
				aesAlg: params.aesAlg,
				plaintext,
				cipherKey: cek,
				iv,
				aad
			})
		}
		default:
			// Should never reach here
			throw new Error(`Unsupported encryption algorithm: ${enc}`)
	}
}
