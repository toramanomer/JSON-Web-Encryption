import { describe, it, expect } from 'vitest'
import { concatKdf } from './concatKdf.js'
import { Buffer } from 'node:buffer'

describe('concatKdf', () => {
	// Valid test cases
	describe('successful derivation', () => {
		// RFC 7518 Appendix C
		it('should derive correct key', () => {
			expect(
				concatKdf({
					sharedSecret: Buffer.from([
						158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131,
						191, 132, 38, 156, 251, 49, 110, 163, 218, 128, 106, 72,
						246, 218, 167, 121, 140, 254, 144, 196
					]),
					derivedKeyBits: 128,
					otherInfo: Buffer.from([
						0, 0, 0, 7, 65, 49, 50, 56, 71, 67, 77, 0, 0, 0, 5, 65,
						108, 105, 99, 101, 0, 0, 0, 3, 66, 111, 98, 0, 0, 0, 128
					])
				})
			).toStrictEqual(
				Buffer.from([
					86, 170, 141, 234, 248, 35, 109, 32, 92, 34, 40, 205, 113,
					167, 16, 26
				])
			)
		})

		it('should derive key material of requested length', () => {
			const sharedSecret = Buffer.from('0123456789abcdef', 'hex')
			const derivedKeyBits = 256
			const otherInfo = Buffer.from('algorithm123', 'utf8')

			const result = concatKdf({
				sharedSecret,
				derivedKeyBits,
				otherInfo
			})

			expect(Buffer.isBuffer(result)).toBe(true)
			expect(result.length).toBe(derivedKeyBits / 8)
		})

		it('should handle non-multiple-of-8 key lengths', () => {
			const sharedSecret = Buffer.from('0123456789abcdef', 'hex')
			const derivedKeyBits = 20 // Not a multiple of 8
			const otherInfo = Buffer.from('algorithm123', 'utf8')

			const result = concatKdf({
				sharedSecret,
				derivedKeyBits,
				otherInfo
			})

			expect(Buffer.isBuffer(result)).toBe(true)
			expect(result.length).toBe(derivedKeyBits >> 3)
		})

		it('should produce deterministic output for same input', () => {
			const input = {
				sharedSecret: Buffer.from('0123456789abcdef', 'hex'),
				derivedKeyBits: 256,
				otherInfo: Buffer.from('algorithm123', 'utf8')
			}

			const result1 = concatKdf(input)
			const result2 = concatKdf(input)

			expect(result1).toEqual(result2)
		})

		it('should handle minimum valid key length', () => {
			const result = concatKdf({
				sharedSecret: Buffer.from('0123456789abcdef', 'hex'),
				derivedKeyBits: 8, // Minimum valid length (1 byte)
				otherInfo: Buffer.from('algorithm123', 'utf8')
			})

			expect(result.length).toBe(1)
		})

		it('should handle large key lengths', () => {
			const result = concatKdf({
				sharedSecret: Buffer.from('0123456789abcdef', 'hex'),
				derivedKeyBits: 1024, // Multiple hash blocks needed
				otherInfo: Buffer.from('algorithm123', 'utf8')
			})

			expect(result.length).toBe(128) // 1024 bits = 128 bytes
		})
	})

	// Error cases
	describe('error cases', () => {
		it('should throw on non-Buffer sharedSecret', () => {
			const invalidInput = {
				sharedSecret: '0123456789abcdef' as unknown as Buffer,
				derivedKeyBits: 256,
				otherInfo: Buffer.from('algorithm123', 'utf8')
			}

			expect(() => concatKdf(invalidInput)).toThrow()
		})

		it('should throw on non-Buffer otherInfo', () => {
			const invalidInput = {
				sharedSecret: Buffer.from('0123456789abcdef', 'hex'),
				derivedKeyBits: 256,
				otherInfo: 'algorithm123' as unknown as Buffer
			}

			expect(() => concatKdf(invalidInput)).toThrow()
		})

		it('should throw on non-integer derivedKeyBits', () => {
			const invalidInput = {
				sharedSecret: Buffer.from('0123456789abcdef', 'hex'),
				derivedKeyBits: 256.5,
				otherInfo: Buffer.from('algorithm123', 'utf8')
			}

			expect(() => concatKdf(invalidInput)).toThrow()
		})

		it('should throw on negative derivedKeyBits', () => {
			expect(() =>
				concatKdf({
					sharedSecret: Buffer.from('0123456789abcdef', 'hex'),
					derivedKeyBits: -256,
					otherInfo: Buffer.from('algorithm123', 'utf8')
				})
			).toThrow()
		})

		it('should throw on zero derivedKeyBits', () => {
			expect(() =>
				concatKdf({
					sharedSecret: Buffer.from('0123456789abcdef', 'hex'),
					derivedKeyBits: 0,
					otherInfo: Buffer.from('algorithm123', 'utf8')
				})
			).toThrow()
		})

		it('should throw when requested key length is too long', () => {
			const maxHashBlocks = Math.pow(2, 32) - 1
			expect(() =>
				concatKdf({
					sharedSecret: Buffer.from('0123456789abcdef', 'hex'),
					derivedKeyBits: (maxHashBlocks + 1) * 256, // Exceeds maximum blocks
					otherInfo: Buffer.from('algorithm123', 'utf8')
				})
			).toThrow()
		})

		it('should throw when total input length exceeds maximum', () => {
			// Create large buffers that when combined exceed maxHashInputBits
			const largeBuffer = Buffer.alloc(2 ** 31) // 2GB buffer
			expect(() =>
				concatKdf({
					sharedSecret: largeBuffer,
					derivedKeyBits: 256,
					otherInfo: largeBuffer // Combined with counter and sharedSecret exceeds max
				})
			).toThrow()
		})
	})

	// Edge cases
	describe('edge cases', () => {
		it('should handle empty otherInfo', () => {
			const result = concatKdf({
				sharedSecret: Buffer.from('0123456789abcdef', 'hex'),
				derivedKeyBits: 256,
				otherInfo: Buffer.alloc(0)
			})

			expect(Buffer.isBuffer(result)).toBe(true)
			expect(result.length).toBe(32) // 256 bits = 32 bytes
		})

		it('should handle minimum size shared secret', () => {
			const result = concatKdf({
				sharedSecret: Buffer.from([1]), // Single byte
				derivedKeyBits: 256,
				otherInfo: Buffer.from('algorithm123', 'utf8')
			})

			expect(Buffer.isBuffer(result)).toBe(true)
			expect(result.length).toBe(32)
		})

		it('should handle key length not multiple of hash output', () => {
			const result = concatKdf({
				sharedSecret: Buffer.from('0123456789abcdef', 'hex'),
				derivedKeyBits: 384, // 1.5 hash blocks
				otherInfo: Buffer.from('algorithm123', 'utf8')
			})

			expect(result.length).toBe(48) // 384 bits = 48 bytes
		})
	})
})
