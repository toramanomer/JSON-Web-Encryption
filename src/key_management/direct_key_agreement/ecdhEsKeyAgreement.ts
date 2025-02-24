import { Buffer } from 'node:buffer'
import { isKeyObject } from 'node:util/types'
import {
	KeyObject,
	createSecretKey,
	diffieHellman,
	generateKeyPairSync
} from 'node:crypto'
import { createEmptyBuffer } from '../../common/utils/createEmptyBuffer.js'
import {
	encHeaderParameters,
	EncHeaderParameterValues
} from '../../common/constants/enc.js'
import { concatKdf } from '../../common/crypto/concatKdf.js'
import { lengthPrefixed } from '../../common/utils/lengthPrefixed.js'

type EcdhEsKeyAgreementInput = {
	recipientPublicKey: KeyObject
	enc: EncHeaderParameterValues
	apu?: string
	apv?: string
}

export const ecdhEsKeyAgreement = ({
	recipientPublicKey,
	enc,
	apu,
	apv
}: EcdhEsKeyAgreementInput) => {
	if (!isKeyObject(recipientPublicKey))
		throw new TypeError('recipientPublicKey must be a KeyObject')
	if (recipientPublicKey.type !== 'public')
		throw new TypeError('recipientPublicKey must be a public KeyObject')
	if (recipientPublicKey.asymmetricKeyType !== 'ec')
		throw new TypeError('recipientPublicKey must be of type ec')
	const namedCurve = recipientPublicKey.asymmetricKeyDetails?.namedCurve
	if (!namedCurve) throw new Error('Could not determine the curve algorithm')
	const curves = ['P-256', 'P-384', 'P-521']
	if (!curves.includes(namedCurve))
		throw new Error('The curve algorithm is not supported')

	const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve })
	const sharedSecret = diffieHellman({
		privateKey,
		publicKey: recipientPublicKey
	})

	const { cekBytes } = encHeaderParameters[enc]
	const derivedKeyBits = cekBytes * 8

	const algorithmId = lengthPrefixed(Buffer.from(enc))
	const partyUInfo = lengthPrefixed(
		apu ? Buffer.from(apu, 'base64url') : createEmptyBuffer()
	)
	const partyVInfo = lengthPrefixed(
		apv ? Buffer.from(apv, 'base64url') : createEmptyBuffer()
	)
	const suppPubInfo = Buffer.alloc(4)
	suppPubInfo.writeUInt32BE(derivedKeyBits, 0)
	const suppPrivInfo = createEmptyBuffer()
	const otherInfo = Buffer.concat([
		algorithmId,
		partyUInfo,
		partyVInfo,
		suppPubInfo,
		suppPrivInfo
	])

	const cek = concatKdf({ sharedSecret, derivedKeyBits, otherInfo })

	return {
		cek: createSecretKey(cek),
		jweEncryptedKey: createEmptyBuffer(),
		additionalHeaderParams: { epk: publicKey.export({ format: 'jwk' }) }
	}
}
