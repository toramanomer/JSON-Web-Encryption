import { describe, it, expect } from 'vitest'
import { generateIV } from './generateIV.js'

describe('generateIV', () => {
	const bytes = 32
	const iv = generateIV(bytes)
	it('should generate a random bytes of specifies length:', () => {
		expect(iv).toHaveLength(32)
	})
	it('should return a buffer', () => {
		expect(iv).toBeInstanceOf(Buffer)
	})
})
