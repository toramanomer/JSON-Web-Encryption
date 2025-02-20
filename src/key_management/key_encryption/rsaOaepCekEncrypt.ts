import type { KeyObject } from 'node:crypto'
import { publicEncrypt } from 'node:crypto'
import { isKeyObject } from 'node:util/types'
import { rsaOaepCekEncryptAlgs } from '../../common/constants/alg.js'

type RsaOaepCekEncryptInput = {
	alg: keyof typeof rsaOaepCekEncryptAlgs
	keyEncryptionKey: KeyObject
	contentEncryptionKey: KeyObject
}

export const rsaOaepCekEncrypt = ({
	alg,
	contentEncryptionKey,
	keyEncryptionKey
}: RsaOaepCekEncryptInput) => {
	if (!isKeyObject(contentEncryptionKey))
		throw new TypeError(
			'Invalid contentEncryptionKey: Expected a KeyObject.'
		)

	if (!isKeyObject(keyEncryptionKey))
		throw new TypeError('Invalid keyEncryptionKey: Expected a KeyObject.')
	if (keyEncryptionKey.type !== 'public')
		throw new TypeError(
			'Invalid keyEncryptionKey: Expected a public RSA key.'
		)
	if (keyEncryptionKey.asymmetricKeyType !== 'rsa')
		throw new TypeError(
			`Invalid key type: Expected an RSA key, but got ${keyEncryptionKey.asymmetricKeyType}.`
		)

	const keySize = keyEncryptionKey.asymmetricKeyDetails?.modulusLength
	if (!keySize || keySize < 2048)
		throw new TypeError(
			`Invalid RSA key size: ${keySize} bits. Must be at least 2048 bits.`
		)

	const algConfig = rsaOaepCekEncryptAlgs[alg]
	if (!algConfig) throw new TypeError(`Unsupported algorithm: ${alg}`)

	const { oaepHash, padding } = rsaOaepCekEncryptAlgs[alg]

	return {
		jweEncryptedKey: publicEncrypt(
			{ key: keyEncryptionKey, oaepHash, padding },
			contentEncryptionKey.export()
		)
	}
}
