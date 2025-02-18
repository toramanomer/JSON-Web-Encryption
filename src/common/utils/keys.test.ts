import { describe, it, expect } from 'vitest'
import { keys } from './keys.js'

describe('keys', () => {
	it('should return the correct keys for an object.', () => {
		expect(keys({ alg: 'Alg', enc: 'Enc' })).toEqual(
			expect.arrayContaining(['enc', 'alg'])
		)
	})
})
