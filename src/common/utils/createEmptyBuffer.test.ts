import { describe, it, expect } from 'vitest'
import { createEmptyBuffer } from './createEmptyBuffer.js'

describe('createEmptyBuffer', () => {
	it('should return a buffer with length 0', () => {
		const buffer = createEmptyBuffer()
		expect(buffer.length).toBe(0)
	})

	it('should return a buffer with no content', () => {
		const buffer = createEmptyBuffer()
		expect(buffer.toString()).toBe('')
		expect(buffer.toString('base64url')).toBe('')
	})
})
