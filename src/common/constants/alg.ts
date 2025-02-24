import { constants } from 'node:crypto'
import { hashAlgs } from './hashAlgs.js'

export const aesKeyWrapAlgs = Object.freeze({
	A128KW: Object.freeze({ aesAlg: 'aes128-wrap' }),
	A192KW: Object.freeze({ aesAlg: 'aes192-wrap' }),
	A256KW: Object.freeze({ aesAlg: 'aes256-wrap' })
})

export const aesGcmKeyWrapAlgs = Object.freeze({
	A128GCMKW: Object.freeze({ aesAlg: 'aes-128-gcm' }),
	A192GCMKW: Object.freeze({ aesAlg: 'aes-192-gcm' }),
	A256GCMKW: Object.freeze({ aesAlg: 'aes-256-gcm' })
})

export const rsaOaepCekEncryptAlgs = Object.freeze({
	'RSA-OAEP': Object.freeze({
		oaepHash: hashAlgs.sha1,
		padding: constants.RSA_PKCS1_OAEP_PADDING
	}),
	'RSA-OAEP-256': Object.freeze({
		oaepHash: hashAlgs.sha256,
		padding: constants.RSA_PKCS1_OAEP_PADDING
	})
})

export const pbes2KeyWrapAlgs = Object.freeze({
	'PBES2-HS256+A128KW': Object.freeze({
		hmacHashAlg: hashAlgs.sha256,
		minSaltInputBytes: 8,
		requestedBytes: 16,
		aesAlg: 'aes128-wrap'
	}),
	'PBES2-HS384+A192KW': Object.freeze({
		hmacHashAlg: hashAlgs.sha384,
		minSaltInputBytes: 8,
		requestedBytes: 24,
		aesAlg: 'aes192-wrap'
	}),
	'PBES2-HS512+A256KW': Object.freeze({
		hmacHashAlg: hashAlgs.sha512,
		minSaltInputBytes: 8,
		requestedBytes: 32,
		aesAlg: 'aes256-wrap'
	})
})
