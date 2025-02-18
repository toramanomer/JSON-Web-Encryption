import { describe, expect, it } from 'vitest'
import { isBuffer } from './isBuffer.js'

describe('isBuffer', () => {
	it.each([
		{ value: Buffer.alloc(0), expected: true },
		{ value: Buffer.from([]), expected: true },
		{ value: Buffer.from(''), expected: true },
		{ value: '', expected: false }
	])('should return $expected for $value', ({ value, expected }) => {
		expect(isBuffer(value)).toBe(expected)
	})
})
