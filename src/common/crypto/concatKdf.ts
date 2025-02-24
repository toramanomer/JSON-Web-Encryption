import { createHash, Hash } from 'node:crypto'
import { Buffer } from 'node:buffer'
import { hashAlgs } from '../constants/hashAlgs.js'

const sha256 = (data: Buffer) =>
	createHash(hashAlgs.sha256).update(data).digest()

/**
 * the length (in bits) of the output of of sha256
 */
const hashOutputBits = 256

/**
 * The maximum length (in bits) of the input to sha256
 */
const maxHashInputBits = 18446744073709551615n

type ConcatKDFInput = {
	/**
	 * The shared secret between the two parties.
	 */
	sharedSecret: Buffer

	/**
	 * A positive integer specifying the desired length (in bits) of the
	 * derived keying material.
	 */
	derivedKeyBits: number

	/**
	 * Additional information used in the key derivation process.
	 * This typically includes algorithm ID, party info, and other context-specific data.
	 */
	otherInfo: Buffer
}

export const concatKdf = ({
	sharedSecret,
	derivedKeyBits,
	otherInfo
}: ConcatKDFInput) => {
	// Validate input types
	if (!Buffer.isBuffer(sharedSecret))
		throw new TypeError('sharedSecret must be a Buffer')

	if (!Buffer.isBuffer(otherInfo))
		throw new TypeError('otherInfo must be a Buffer')

	if (!Number.isInteger(derivedKeyBits))
		throw new TypeError('derivedKeyBits must be an integer')

	// Validate derivedKeyBits
	if (derivedKeyBits <= 0) throw new Error('derivedKeyBits must be positive')

	// Calculate the number of hash function blocks needed
	const reps = Math.ceil(derivedKeyBits / hashOutputBits)
	if (reps > Math.pow(2, 32) - 1)
		throw new RangeError('Requested key length is too long.')

	const counter = Buffer.alloc(4) // 32-bit counter
	const hashInputBits = BigInt(
		(counter.length + sharedSecret.length + otherInfo.length) * 8
	)
	if (hashInputBits > maxHashInputBits)
		throw new Error('Input length is too large')

	const result = [Buffer.alloc(0)]
	for (let i = 1; i <= reps; i++) {
		counter.writeUint32BE(counter.readUint32BE() + 1)
		const ki = sha256(Buffer.concat([counter, sharedSecret, otherInfo]))
		result[i] = Buffer.concat([result[i - 1], ki])
	}

	return result[reps].subarray(0, derivedKeyBits >> 3)
}
