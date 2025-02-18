import { Buffer } from 'node:buffer'
import { describe, it, expect } from 'vitest'
import { toBase64Url } from './toBase64Url.js'

describe('toBase64Url', () => {
	// Taken from Test Vectors in RFC 4648
	const testVectors = [
		{ value: '', base64: '' },
		{ value: 'f', base64: 'Zg==' },
		{ value: 'fo', base64: 'Zm8=' },
		{ value: 'foo', base64: 'Zm9v' },
		{ value: 'foob', base64: 'Zm9vYg==' },
		{ value: 'fooba', base64: 'Zm9vYmE=' },
		{ value: 'foobar', base64: 'Zm9vYmFy' }
	].map(({ value, base64 }) => ({
		value,
		expected: base64
			.replace(/\+/g, '-')
			.replace(/\//g, '_')
			.replace(/=+$/, '')
	}))

	it.each(testVectors)(
		'should correctly convert $value to base64url',
		({ value, expected }) => {
			expect(toBase64Url(value)).toBe(expected)
			expect(toBase64Url(Buffer.from(value))).toBe(expected)
		}
	)
})
