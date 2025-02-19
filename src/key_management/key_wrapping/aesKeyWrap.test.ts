import { Buffer } from 'node:buffer'
import { createPublicKey, createSecretKey } from 'node:crypto'
import { describe, it, expect } from 'vitest'
import { aesKeyWrap } from './aesKeyWrap.js'

const bufferFromHex = (data: string) => Buffer.from(data, 'hex')

// Test Vectors taken from RFC 3394 Section 4
const testVectors = (
	[
		{
			aesAlg: 'aes128-wrap',
			keyEncryptionKey: '000102030405060708090A0B0C0D0E0F',
			keyData: '00112233445566778899AABBCCDDEEFF',
			expected: '1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5'
		},
		{
			aesAlg: 'aes192-wrap',
			keyEncryptionKey:
				'000102030405060708090A0B0C0D0E0F1011121314151617',
			keyData: '00112233445566778899AABBCCDDEEFF',
			expected: '96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D'
		},
		{
			aesAlg: 'aes256-wrap',
			keyEncryptionKey:
				'000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F',
			keyData: '00112233445566778899AABBCCDDEEFF',
			expected: '64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7'
		},
		{
			aesAlg: 'aes192-wrap',
			keyEncryptionKey:
				'000102030405060708090A0B0C0D0E0F1011121314151617',
			keyData: '00112233445566778899AABBCCDDEEFF0001020304050607',
			expected:
				'031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2'
		},
		{
			aesAlg: 'aes256-wrap',
			keyEncryptionKey:
				'000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F',
			keyData: '00112233445566778899AABBCCDDEEFF0001020304050607',
			expected:
				'A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1'
		},
		{
			aesAlg: 'aes256-wrap',
			keyEncryptionKey:
				'000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F',
			keyData:
				'00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F',
			expected:
				'28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21'
		}
	] as const
).map(({ aesAlg, keyData, keyEncryptionKey, expected }) => ({
	aesAlg,
	keyData: bufferFromHex(keyData),
	keyEncryptionKey: bufferFromHex(keyEncryptionKey),
	expected: bufferFromHex(expected)
}))

describe('Key Wrapping with AES Key Wrap', () => {
	describe.each(testVectors)(
		'When wrapping $keyData.length bytes of Key Data with a $keyEncryptionKey.length-byte KEK',
		({ aesAlg, keyData, keyEncryptionKey, expected }) => {
			const wrapped = aesKeyWrap({
				aesAlg,
				keyData,
				keyEncryptionKey: createSecretKey(keyEncryptionKey)
			})

			it('should produce the expected wrapped key', () => {
				expect(wrapped).toStrictEqual({
					jweEncryptedKey: expected
				})
			})

			it('should produce an output 8 bytes longer than the input key data', () => {
				expect(wrapped.jweEncryptedKey).toHaveLength(keyData.length + 8)
			})
		}
	)

	describe('When wrapping with 8 bytes of Key Data', () => {
		it('should throw an error', () => {
			const [{ aesAlg, keyEncryptionKey }] = testVectors
			expect(() =>
				aesKeyWrap({
					aesAlg,
					keyData: Buffer.alloc(8),
					keyEncryptionKey: createSecretKey(keyEncryptionKey)
				})
			).toThrow()
		})
	})

	describe('When wrapping Key Data that is not a multiple of 8 bytes', () => {
		it('should throw an error', () => {
			const [{ aesAlg, keyEncryptionKey }] = testVectors
			expect(() =>
				aesKeyWrap({
					aesAlg,
					keyData: Buffer.alloc(8 * 8 + 1),
					keyEncryptionKey: createSecretKey(keyEncryptionKey)
				})
			).toThrow()
		})
	})

	describe('When KEK is not a KeyObject', () => {
		it('should throw an error', () => {
			const [{ aesAlg, keyData, keyEncryptionKey }] = testVectors
			expect(() =>
				aesKeyWrap({
					aesAlg,
					keyData,
					// @ts-expect-error
					keyEncryptionKey
				})
			).toThrow()
		})
	})

	describe('When KEK is not a symmetric KeyObject', () => {
		it('should throw an error', () => {
			const [{ aesAlg, keyData, keyEncryptionKey }] = testVectors
			expect(() =>
				aesKeyWrap({
					aesAlg,
					keyData,
					keyEncryptionKey: createPublicKey(keyEncryptionKey)
				})
			).toThrow()
		})
	})
})
