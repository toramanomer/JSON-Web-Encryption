import { describe, it, expect } from 'vitest'
import { generateHmacKey } from './generateHmacKey.js'

const keyBytes = [16, 24, 32]

describe.for(keyBytes)(
	'when generateHmacKey is called with %i (bytes)',
	keyByte => {
		const key = generateHmacKey(keyByte)

		it('should generate a key with the correct byte length', () => {
			expect(key.symmetricKeySize).toBe(keyByte)
		})

		it('should return a KeyObject of type "secret"', () => {
			expect(key.type).toBe('secret')
		})
	}
)
