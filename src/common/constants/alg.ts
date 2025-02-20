import { constants } from 'node:crypto'
import { hashAlgs } from './hashAlgs.js'

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
