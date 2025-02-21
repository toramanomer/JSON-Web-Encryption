import { generateKeySync } from 'node:crypto'

// Generates a symmetric HMAC key of the given byte length.
export const generateHmacKey = (bytes: number) =>
	generateKeySync('hmac', { length: bytes * 8 })
