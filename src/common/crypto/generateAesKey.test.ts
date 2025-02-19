import { describe, it, expect } from 'vitest'
import { generateAesKey } from './generateAesKey.js'

const keyBytes = [16, 24, 32] as const

describe.for(keyBytes)(
	'when generateAesKey is called with %i (bytes)',
	keyByte => {
		const key = generateAesKey(keyByte)

		it('should generate a key with the correct byte length', () => {
			expect(key.symmetricKeySize).toBe(keyByte)
		})

		it('should return a KeyObject of type "secret"', () => {
			expect(key.type).toBe('secret')
		})
	}
)
