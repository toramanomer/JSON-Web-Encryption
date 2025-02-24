import { Buffer } from 'node:buffer'
import { describe, it, expect } from 'vitest'
import { lengthPrefixed } from './lengthPrefixed.js'

describe('lengthPrefixed', () => {
	it('should prefix buffer with its length', () => {
		const data = Buffer.from('Hello, World!')
		const result = lengthPrefixed(data)

		// Expected length prefix (13 in BE uint32)
		const expectedPrefix = Buffer.alloc(4)
		expectedPrefix.writeUInt32BE(13)

		// Check total length (4 bytes prefix + data length)
		expect(result.length).toBe(4 + data.length)

		// Check prefix bytes
		expect(result.subarray(0, 4)).toEqual(expectedPrefix)

		// Check data bytes
		expect(result.subarray(4)).toEqual(data)
	})

	it('should handle empty buffer', () => {
		const data = Buffer.from('')
		const result = lengthPrefixed(data)

		// Expected length prefix (0 in BE uint32)
		const expectedPrefix = Buffer.alloc(4)
		expectedPrefix.writeUInt32BE(0)

		expect(result.length).toBe(4)
		expect(result).toEqual(expectedPrefix)
	})

	it('should handle large buffers', () => {
		const data = Buffer.alloc(1000000) // 1MB of zeros
		const result = lengthPrefixed(data)

		const expectedPrefix = Buffer.alloc(4)
		expectedPrefix.writeUInt32BE(1000000)

		expect(result.length).toBe(4 + data.length)
		expect(result.subarray(0, 4)).toEqual(expectedPrefix)
		expect(result.subarray(4)).toEqual(data)
	})
})
