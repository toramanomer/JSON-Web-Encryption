import { KeyObject } from 'crypto'
import { ecdhEsKeyAgreement } from '../direct_key_agreement/ecdhEsKeyAgreement.js'
import { aesKeyWrap } from '../key_wrapping/aesKeyWrap.js'
import { ecdhEsKeyAgreementWithKeyWrapAlgs } from '../../common/constants/alg.js'

type EcdhEsKeyAgreementWithKeyWrapInput = {
	recipientPublicKey: KeyObject
	cek: KeyObject
	apu?: string
	apv?: string
	alg: keyof typeof ecdhEsKeyAgreementWithKeyWrapAlgs
}
export const ecdhEsKeyAgreementWithKeyWrap = ({
	recipientPublicKey,
	cek,
	alg,
	apu,
	apv
}: EcdhEsKeyAgreementWithKeyWrapInput) => {
	const { aesAlg, derivedKeyBits } = ecdhEsKeyAgreementWithKeyWrapAlgs[alg]
	const { cek: keyEncryptionKey, additionalHeaderParams } =
		ecdhEsKeyAgreement({
			recipientPublicKey,
			derivedKeyBits,
			enc: alg,
			apu,
			apv
		})

	const { jweEncryptedKey } = aesKeyWrap({
		aesAlg,
		keyData: cek.export(),
		keyEncryptionKey
	})
	return { jweEncryptedKey, additionalHeaderParams }
}
