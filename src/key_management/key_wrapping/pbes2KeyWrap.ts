import { Buffer } from 'node:buffer'
import { createSecretKey, pbkdf2Sync } from 'node:crypto'
import { isBuffer } from '../../common/utils/isBuffer.js'
import { toBase64Url } from '../../common/utils/toBase64Url.js'
import { pbes2KeyWrapAlgs } from '../../common/constants/alg.js'
import { aesKeyWrap } from './aesKeyWrap.js'

type Pbes2KeyWrapInput = {
	password: Buffer

	cek: Buffer

	alg: keyof typeof pbes2KeyWrapAlgs

	/**
	 * Buffer representing the "p2s" (PBES2 Salt Input) Header Parameter
	 *
	 * - It must be at least 8 bytes.
	 * - A new Salt Input value MUST be generated randomly for every encryption operation.
	 * @default 24 bytes
	 */
	saltInput: Buffer

	/**
	 * "p2c" (PBES2 Count) Header Parameter
	 *
	 * The number of iterations for the PBKDF2 key derivation function.
	 * - A minimum iteration count of 1000 is recommended.
	 */
	iterations?: number
}

export const pbes2KeyWrap = ({
	password,
	cek,
	alg,
	saltInput,
	iterations
}: Pbes2KeyWrapInput) => {
	// Validate password
	if (!isBuffer(password)) throw new TypeError('password must be a Buffer.')

	// Validate alg
	if (!pbes2KeyWrapAlgs[alg])
		throw new TypeError(`Unsupported PBES2 Key Wrap Algorithm: ${alg}.`)

	const { aesAlg, minSaltInputBytes, hmacHashAlg, requestedBytes } =
		pbes2KeyWrapAlgs[alg]

	// Validate Salt Input
	if (!isBuffer(saltInput)) throw new TypeError('saltInput must be a Buffer.')
	if (saltInput.length < minSaltInputBytes)
		throw new RangeError(
			`saltInput must be at least ${minSaltInputBytes} bytes.`
		)

	// Validate Iterations
	if (!iterations || typeof iterations !== 'number')
		throw new TypeError('iterations must be a number.')
	if (iterations <= 0)
		throw new RangeError('iterations must be a positive integer.')
	if (!Number.isInteger(iterations))
		throw new RangeError('iterations must be an integer.')

	const salt = Buffer.concat([
		Buffer.from(alg),
		Buffer.alloc(1, 0x00),
		saltInput
	])

	const derivedKey = pbkdf2Sync(
		password,
		salt,
		iterations,
		requestedBytes,
		hmacHashAlg
	)
	const { jweEncryptedKey } = aesKeyWrap({
		aesAlg,
		keyData: cek,
		keyEncryptionKey: createSecretKey(derivedKey)
	})

	return {
		jweEncryptedKey,
		additionalHeaderParams: { p2s: toBase64Url(saltInput), p2c: iterations }
	}
}
