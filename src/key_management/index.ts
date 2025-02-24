import { KeyObject, randomBytes } from 'node:crypto'
import { type EncHeaderParameterValues } from '../common/constants/enc.js'
import {
	type AlgHeaderParameter,
	algHeaderParameters
} from '../common/constants/index.js'

import { aesGcmKeyWrapAlgs, aesKeyWrapAlgs } from '../common/constants/alg.js'

import { generateCek } from './generateCek.js'

import { aesKeyWrap } from './key_wrapping/aesKeyWrap.js'
import { aesGcmKeyWrap } from './key_wrapping/aesGcmKeyWrap.js'
import { pbes2KeyWrap } from './key_wrapping/pbes2KeyWrap.js'
import { rsaOaepCekEncrypt } from './key_encryption/rsaOaepCekEncrypt.js'
import { ecdhEsKeyAgreement } from './direct_key_agreement/ecdhEsKeyAgreement.js'
import { directKeyEncryption } from './direct_encryption/directKeyEncryption.js'

type GenerateCekInput = {
	alg: AlgHeaderParameter
	enc: EncHeaderParameterValues
	key: KeyObject
	apu?: string
	apv?: string
}

type GenerateCekOuput = {
	cek: KeyObject
	jweEncryptedKey: Buffer
	additionalHeaderParams?: {
		iv?: string
		tag?: string
		p2s?: string
		p2c?: number
		epk?: any
	}
}

export const handleKeyManagement = ({
	alg,
	enc,
	key,
	apu,
	apv
}: GenerateCekInput): GenerateCekOuput => {
	switch (alg) {
		// Key Wrapping
		case algHeaderParameters.A128KW:
		case algHeaderParameters.A192KW:
		case algHeaderParameters.A256KW: {
			const cek = generateCek(enc)
			const { aesAlg } = aesKeyWrapAlgs[alg]
			const { jweEncryptedKey } = aesKeyWrap({
				aesAlg,
				keyData: cek.export(),
				keyEncryptionKey: key
			})
			return { cek, jweEncryptedKey }
		}

		// Key Wrapping
		case algHeaderParameters.A128GCMKW:
		case algHeaderParameters.A192GCMKW:
		case algHeaderParameters.A256GCMKW: {
			const cek = generateCek(enc)
			const { aesAlg } = aesGcmKeyWrapAlgs[alg]
			const { jweEncryptedKey, additionalHeaderParams } = aesGcmKeyWrap({
				aesAlg,
				contentEncryptionKey: cek,
				keyEncryptionKey: key
			})
			return { cek, jweEncryptedKey, additionalHeaderParams }
		}

		// Key Wrapping
		case algHeaderParameters['PBES2-HS256+A128KW']:
		case algHeaderParameters['PBES2-HS384+A192KW']:
		case algHeaderParameters['PBES2-HS512+A256KW']: {
			const cek = generateCek(enc)
			const { jweEncryptedKey, additionalHeaderParams } = pbes2KeyWrap({
				password: key.export(),
				cek: cek.export(),
				alg,
				saltInput: randomBytes(42),
				iterations: 4096
			})
			return { cek, jweEncryptedKey, additionalHeaderParams }
		}

		// Key Encryption
		case algHeaderParameters['RSA-OAEP']:
		case algHeaderParameters['RSA-OAEP-256']: {
			const cek = generateCek(enc)
			const { jweEncryptedKey } = rsaOaepCekEncrypt({
				alg,
				contentEncryptionKey: key,
				keyEncryptionKey: cek
			})
			return { cek, jweEncryptedKey }
		}

		// Direct Key Agreement
		case algHeaderParameters['ECDH-ES']: {
			const { cek, jweEncryptedKey, additionalHeaderParams } =
				ecdhEsKeyAgreement({ recipientPublicKey: key, enc, apu, apv })
			return { cek, jweEncryptedKey, additionalHeaderParams }
		}

		// Key Agreement with Key Wrapping
		case algHeaderParameters['ECDH-ES+A128KW']:
		case algHeaderParameters['ECDH-ES+A192KW']:
		case algHeaderParameters['ECDH-ES+A256KW']: {
			throw new Error('Not implemented yet')
		}

		// Direct Encryption
		case algHeaderParameters.dir:
			const { jweEncryptedKey } = directKeyEncryption()
			return { cek: key, jweEncryptedKey }

		default:
			// Should never happen
			throw new TypeError(`Unsupported alg: ${alg}`)
	}
}
