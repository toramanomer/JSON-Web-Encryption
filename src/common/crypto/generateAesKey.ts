import { generateKeySync } from 'node:crypto'

// Generates a symmetric AES key of the given byte length.
export const generateAesKey = (bytes: 16 | 24 | 32) =>
	generateKeySync('aes', { length: bytes * 8 })
