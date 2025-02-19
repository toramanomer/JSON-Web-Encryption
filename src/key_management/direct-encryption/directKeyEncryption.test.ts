import {} from 'node:buffer'
import { describe, it, expect } from 'vitest'
import { directKeyEncryption } from './directKeyEncryption.js'

describe('When directKeyEncryption is called', () => {
	it('should return an object with jweEncryptedKey property set to empty buffer', () => {
		expect(directKeyEncryption()).toStrictEqual({
			jweEncryptedKey: Buffer.alloc(0)
		})
	})
})
