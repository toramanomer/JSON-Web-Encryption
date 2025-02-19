import { Buffer } from 'node:buffer'
import {
	createPrivateKey,
	createPublicKey,
	createSecretKey,
	generateKeySync,
	randomBytes
} from 'node:crypto'
import { describe, it, expect } from 'vitest'
import { aesGcmEncrypt } from './aesGcmEncrypt.js'

const aesAlgs = ['aes-128-gcm', 'aes-192-gcm', 'aes-256-gcm'] as const

const aes128 = 'aes-128-gcm'
const aes256 = 'aes-256-gcm'
const bufFromHex = (data: string) => Buffer.from(data, 'hex')

describe('Content Encryption with AES GCM', () => {
	describe('Error Cases', () => {
		describe('When Cipher Key is not a KeyObject', () => {
			it.for(aesAlgs)('should throw an error for %s', aesAlg => {
				expect(() =>
					aesGcmEncrypt({
						aesAlg,
						// @ts-expect-error
						cipherKey: Buffer.alloc(16),
						iv: randomBytes(8),
						plaintext: Buffer.alloc(10),
						aad: Buffer.alloc(0)
					})
				).toThrow()
			})
		})

		describe('When Cipher Key is a private key', () => {
			it.for(aesAlgs)('should throw an error for %s', aesAlg => {
				expect(() =>
					aesGcmEncrypt({
						aesAlg,
						cipherKey: createPrivateKey(
							Buffer.alloc(parseInt(aesAlg.slice(4, 7)) / 8)
						),
						iv: randomBytes(8),
						plaintext: Buffer.alloc(10),
						aad: Buffer.alloc(0)
					})
				).toThrow()
			})
		})

		describe('When Cipher Key is a public key', () => {
			it.for(aesAlgs)('should throw an error for %s', aesAlg => {
				expect(() =>
					aesGcmEncrypt({
						aesAlg,
						cipherKey: createPublicKey(
							Buffer.alloc(parseInt(aesAlg.slice(4, 7)) / 8)
						),
						iv: randomBytes(8),
						plaintext: Buffer.alloc(10),
						aad: Buffer.alloc(0)
					})
				).toThrow()
			})
		})

		describe('When IV is not Buffer', () => {
			it.for(aesAlgs)('should throw an error for %s', aesAlg => {
				expect(() =>
					aesGcmEncrypt({
						aesAlg,
						cipherKey: generateKeySync('aes', {
							length: parseInt(aesAlg.slice(4, 7))
						}),
						// @ts-expect-error
						iv: '',
						plaintext: Buffer.alloc(10),
						aad: Buffer.alloc(0)
					})
				).toThrow()
			})
		})

		describe('When IV is not 8 bytes', () => {
			it.for(aesAlgs)('should throw an error for %s', aesAlg => {
				expect(() =>
					aesGcmEncrypt({
						aesAlg,
						cipherKey: generateKeySync('aes', {
							length: parseInt(aesAlg.slice(4, 7))
						}),
						iv: Buffer.alloc(7),
						plaintext: Buffer.alloc(10),
						aad: Buffer.alloc(0)
					})
				).toThrow()
			})
		})

		describe('When Cipher Key length is incorrect', () => {
			it.for(aesAlgs)('should throw an error for %s', aesAlg => {
				expect(() =>
					aesGcmEncrypt({
						aesAlg,
						cipherKey: generateKeySync('aes', { length: 128 * 3 }),
						iv: randomBytes(8),
						plaintext: Buffer.alloc(10),
						aad: Buffer.alloc(0)
					})
				).toThrow()
			})
		})

		describe('When AAD is not buffer', () => {
			it.for(aesAlgs)('should throw an error for %s', aesAlg => {
				expect(() =>
					aesGcmEncrypt({
						aesAlg,
						cipherKey: generateKeySync('aes', {
							length: parseInt(aesAlg.slice(4, 7))
						}),
						iv: randomBytes(8),
						plaintext: Buffer.alloc(10),
						// @ts-expect-error
						aad: ''
					})
				).toThrow()
			})
		})
	})

	it('success', () => {
		const result = aesGcmEncrypt({
			aesAlg: 'aes-256-gcm',
			plaintext: Buffer.from([
				84, 104, 101, 32, 116, 114, 117, 101, 32, 115, 105, 103, 110,
				32, 111, 102, 32, 105, 110, 116, 101, 108, 108, 105, 103, 101,
				110, 99, 101, 32, 105, 115, 32, 110, 111, 116, 32, 107, 110,
				111, 119, 108, 101, 100, 103, 101, 32, 98, 117, 116, 32, 105,
				109, 97, 103, 105, 110, 97, 116, 105, 111, 110, 46
			]),
			cipherKey: createSecretKey(
				Buffer.from([
					177, 161, 244, 128, 84, 143, 225, 115, 63, 180, 3, 255, 107,
					154, 212, 246, 138, 7, 110, 91, 112, 46, 34, 105, 47, 130,
					203, 46, 122, 234, 64, 252
				])
			),
			iv: Buffer.from([
				227, 197, 117, 252, 2, 219, 233, 68, 180, 225, 77, 219
			]),
			aad: Buffer.from([
				101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 83, 85, 48, 69,
				116, 84, 48, 70, 70, 85, 67, 73, 115, 73, 109, 86, 117, 89, 121,
				73, 54, 73, 107, 69, 121, 78, 84, 90, 72, 81, 48, 48, 105, 102,
				81
			])
		})

		expect(result).toStrictEqual({
			jweCiphertext: Buffer.from([
				229, 236, 166, 241, 53, 191, 115, 196, 174, 43, 73, 109, 39,
				122, 233, 96, 140, 206, 120, 52, 51, 237, 48, 11, 190, 219, 186,
				80, 111, 104, 50, 142, 47, 167, 59, 61, 181, 127, 196, 21, 40,
				82, 242, 32, 123, 143, 168, 226, 73, 216, 176, 144, 138, 247,
				106, 60, 16, 205, 160, 109, 64, 63, 192
			]),
			jweAuthenticationTag: Buffer.from([
				92, 80, 104, 49, 133, 25, 161, 215, 173, 101, 219, 211, 136, 91,
				210, 145
			])
		})
	})

	const testVectors = (
		[
			{
				input: {
					aesAlg: aes128,
					key: 'AD7A2BD03EAC835A6F620FDCB506B345',
					plaintext: '',
					aad: 'D609B1F056637A0D46DF998D88E5222AB2C2846512153524C0895E8108000F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F30313233340001',
					iv: '12153524C0895E81B2C28465'
				},
				expected: {
					ciphertext: '',
					tag: 'F09478A9B09007D06F46E9B6A1DA25DD'
				}
			},
			{
				input: {
					aesAlg: aes256,
					key: 'E3C08A8F06C6E3AD95A70557B23F75483CE33021A9C72B7025666204C69C0B72',
					plaintext: '',
					aad: 'D609B1F056637A0D46DF998D88E5222AB2C2846512153524C0895E8108000F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F30313233340001',
					iv: '12153524C0895E81B2C28465'
				},
				expected: {
					ciphertext: '',
					tag: '2F0BC5AF409E06D609EA8B7D0FA5EA50'
				}
			},
			{
				input: {
					aesAlg: aes128,
					key: 'AD7A2BD03EAC835A6F620FDCB506B345',
					plaintext:
						'08000F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A0002',
					aad: 'D609B1F056637A0D46DF998D88E52E00B2C2846512153524C0895E81',
					iv: '12153524C0895E81B2C28465'
				},
				expected: {
					ciphertext:
						'701AFA1CC039C0D765128A665DAB69243899BF7318CCDC81C9931DA17FBE8EDD7D17CB8B4C26FC81E3284F2B7FBA713D',
					tag: '4F8D55E7D3F06FD5A13C0C29B9D5B880'
				}
			},
			{
				input: {
					aesAlg: aes256,
					key: 'E3C08A8F06C6E3AD95A70557B23F75483CE33021A9C72B7025666204C69C0B72',
					plaintext:
						'08000F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A0002',
					aad: 'D609B1F056637A0D46DF998D88E52E00B2C2846512153524C0895E81',
					iv: '12153524C0895E81B2C28465'
				},
				expected: {
					ciphertext:
						'E2006EB42F5277022D9B19925BC419D7A592666C925FE2EF718EB4E308EFEAA7C5273B394118860A5BE2A97F56AB7836',
					tag: '5CA597CDBB3EDB8D1A1151EA0AF7B436'
				}
			},
			{
				input: {
					aesAlg: aes128,
					key: '071B113B0CA743FECCCF3D051F737382',
					plaintext: '',
					aad: 'E20106D7CD0DF0761E8DCD3D88E5400076D457ED08000F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A0003',
					iv: 'F0761E8DCD3D000176D457ED'
				},
				expected: {
					ciphertext: '',
					tag: '0C017BC73B227DFCC9BAFA1C41ACC353'
				}
			},
			{
				input: {
					aesAlg: aes256,
					key: '691D3EE909D7F54167FD1CA0B5D769081F2BDE1AEE655FDBAB80BD5295AE6BE7',
					plaintext: '',
					aad: 'E20106D7CD0DF0761E8DCD3D88E5400076D457ED08000F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A0003',
					iv: 'F0761E8DCD3D000176D457ED'
				},
				expected: {
					ciphertext: '',
					tag: '35217C774BBC31B63166BCF9D4ABED07'
				}
			},
			{
				input: {
					aesAlg: aes128,
					key: '071B113B0CA743FECCCF3D051F737382',
					plaintext:
						'08000F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F30313233340004',
					aad: 'E20106D7CD0DF0761E8DCD3D88E54C2A76D457ED',
					iv: 'F0761E8DCD3D000176D457ED'
				},
				expected: {
					ciphertext:
						'13B4C72B389DC5018E72A171DD85A5D3752274D3A019FBCAED09A425CD9B2E1C9B72EEE7C9DE7D52B3F3',
					tag: 'D6A5284F4A6D3FE22A5D6C2B960494C3'
				}
			},
			{
				input: {
					aesAlg: aes256,
					key: '691D3EE909D7F54167FD1CA0B5D769081F2BDE1AEE655FDBAB80BD5295AE6BE7',
					plaintext:
						'08000F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F30313233340004',
					aad: 'E20106D7CD0DF0761E8DCD3D88E54C2A76D457ED',
					iv: 'F0761E8DCD3D000176D457ED'
				},
				expected: {
					ciphertext:
						'C1623F55730C93533097ADDAD25664966125352B43ADACBD61C5EF3AC90B5BEE929CE4630EA79F6CE519',
					tag: '12AF39C2D1FDC2051F8B7B3C9D397EF2'
				}
			},
			{
				input: {
					aesAlg: aes128,
					key: '013FE00B5F11BE7F866D0CBBC55A7A90',
					plaintext: '',
					aad: '84C5D513D2AAF6E5BBD2727788E523008932D6127CFDE9F9E33724C608000F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F0005',
					iv: '7CFDE9F9E33724C68932D612'
				},
				expected: {
					ciphertext: '',
					tag: '217867E50C2DAD74C28C3B50ABDF695A'
				}
			},
			{
				input: {
					aesAlg: aes256,
					key: '83C093B58DE7FFE1C0DA926AC43FB3609AC1C80FEE1B624497EF942E2F79A823',
					plaintext: '',
					aad: '84C5D513D2AAF6E5BBD2727788E523008932D6127CFDE9F9E33724C608000F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F0005',
					iv: '7CFDE9F9E33724C68932D612'
				},
				expected: {
					ciphertext: '',
					tag: '6EE160E8FAECA4B36C86B234920CA975'
				}
			},
			{
				input: {
					aesAlg: aes128,
					key: '013FE00B5F11BE7F866D0CBBC55A7A90',
					plaintext:
						'08000F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B0006',
					aad: '84C5D513D2AAF6E5BBD2727788E52F008932D6127CFDE9F9E33724C6',
					iv: '7CFDE9F9E33724C68932D612'
				},
				expected: {
					ciphertext:
						'3A4DE6FA32191014DBB303D92EE3A9E8A1B599C14D22FB080096E13811816A3C9C9BCF7C1B9B96DA809204E29D0E2A7642',
					tag: 'BFD310A4837C816CCFA5AC23AB003988'
				}
			},
			{
				input: {
					aesAlg: aes256,
					key: '83C093B58DE7FFE1C0DA926AC43FB3609AC1C80FEE1B624497EF942E2F79A823',
					plaintext:
						'08000F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B0006',
					aad: '84C5D513D2AAF6E5BBD2727788E52F008932D6127CFDE9F9E33724C6',
					iv: '7CFDE9F9E33724C68932D612'
				},
				expected: {
					ciphertext:
						'110222FF8050CBECE66A813AD09A73ED7A9A089C106B959389168ED6E8698EA902EB1277DBEC2E68E473155A15A7DAEED4',
					tag: 'A10F4E05139C23DF00B3AADC71F0596A'
				}
			},
			{
				input: {
					aesAlg: aes128,
					key: '88EE087FD95DA9FBF6725AA9D757B0CD',
					plaintext: '',
					aad: '68F2E77696CE7AE8E2CA4EC588E541002E58495C08000F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D0007',
					iv: '7AE8E2CA4EC500012E58495C'
				},
				expected: {
					ciphertext: '',
					tag: '07922B8EBCF10BB2297588CA4C614523'
				}
			},
			{
				input: {
					aesAlg: aes256,
					key: '4C973DBC7364621674F8B5B89E5C15511FCED9216490FB1C1A2CAA0FFE0407E5',
					plaintext: '',
					aad: '68F2E77696CE7AE8E2CA4EC588E541002E58495C08000F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D0007',
					iv: '7AE8E2CA4EC500012E58495C'
				},
				expected: {
					ciphertext: '',
					tag: '00BDA1B7E87608BCBF470F12157F4C07'
				}
			},
			{
				input: {
					aesAlg: aes128,
					key: '88EE087FD95DA9FBF6725AA9D757B0CD',
					plaintext:
						'08000F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748490008',
					aad: '68F2E77696CE7AE8E2CA4EC588E54D002E58495C',
					iv: '7AE8E2CA4EC500012E58495C'
				},
				expected: {
					ciphertext:
						'C31F53D99E5687F7365119B832D2AAE70741D593F1F9E2AB3455779B078EB8FEACDFEC1F8E3E5277F8180B43361F6512ADB16D2E38548A2C719DBA7228D840',
					tag: '88F8757ADB8AA788D8F65AD668BE70E7'
				}
			},
			{
				input: {
					aesAlg: aes256,
					key: '4C973DBC7364621674F8B5B89E5C15511FCED9216490FB1C1A2CAA0FFE0407E5',
					plaintext:
						'08000F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748490008',
					aad: '68F2E77696CE7AE8E2CA4EC588E54D002E58495C',
					iv: '7AE8E2CA4EC500012E58495C'
				},
				expected: {
					ciphertext:
						'BA8AE31BC506486D6873E4FCE460E7DC57591FF00611F31C3834FE1C04AD80B66803AFCF5B27E6333FA67C99DA47C2F0CED68D531BD741A943CFF7A6713BD0',
					tag: '2611CD7DAA01D61C5C886DC1A8170107'
				}
			}
		] as const
	)
		.map(({ input, expected }) => ({
			input: {
				aesAlg: input.aesAlg,
				cipherKey: createSecretKey(bufFromHex(input.key)),
				plaintext: bufFromHex(input.plaintext),
				aad: bufFromHex(input.aad),
				iv: bufFromHex(input.iv)
			},
			expected: {
				jweCiphertext: bufFromHex(expected.ciphertext),
				jweAuthenticationTag: bufFromHex(expected.tag)
			}
		}))
		.concat({
			input: {
				aesAlg: aes256,
				plaintext: Buffer.from([
					84, 104, 101, 32, 116, 114, 117, 101, 32, 115, 105, 103,
					110, 32, 111, 102, 32, 105, 110, 116, 101, 108, 108, 105,
					103, 101, 110, 99, 101, 32, 105, 115, 32, 110, 111, 116, 32,
					107, 110, 111, 119, 108, 101, 100, 103, 101, 32, 98, 117,
					116, 32, 105, 109, 97, 103, 105, 110, 97, 116, 105, 111,
					110, 46
				]),
				cipherKey: createSecretKey(
					Buffer.from([
						177, 161, 244, 128, 84, 143, 225, 115, 63, 180, 3, 255,
						107, 154, 212, 246, 138, 7, 110, 91, 112, 46, 34, 105,
						47, 130, 203, 46, 122, 234, 64, 252
					])
				),
				iv: Buffer.from([
					227, 197, 117, 252, 2, 219, 233, 68, 180, 225, 77, 219
				]),
				aad: Buffer.from([
					101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 83, 85, 48,
					69, 116, 84, 48, 70, 70, 85, 67, 73, 115, 73, 109, 86, 117,
					89, 121, 73, 54, 73, 107, 69, 121, 78, 84, 90, 72, 81, 48,
					48, 105, 102, 81
				])
			},
			expected: {
				jweCiphertext: Buffer.from([
					229, 236, 166, 241, 53, 191, 115, 196, 174, 43, 73, 109, 39,
					122, 233, 96, 140, 206, 120, 52, 51, 237, 48, 11, 190, 219,
					186, 80, 111, 104, 50, 142, 47, 167, 59, 61, 181, 127, 196,
					21, 40, 82, 242, 32, 123, 143, 168, 226, 73, 216, 176, 144,
					138, 247, 106, 60, 16, 205, 160, 109, 64, 63, 192
				]),
				jweAuthenticationTag: Buffer.from([
					92, 80, 104, 49, 133, 25, 161, 215, 173, 101, 219, 211, 136,
					91, 210, 145
				])
			}
		} as const)

	describe.for(testVectors)(
		'Case Index: %# Alg: $input.aesAlg',
		({ input, expected }) => {
			it('should return expected', () => {
				expect(aesGcmEncrypt(input)).toStrictEqual(expected)
			})
		}
	)
})
