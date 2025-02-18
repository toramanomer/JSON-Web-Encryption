import { Buffer } from 'node:buffer'

// Encodes a string or buffer to base64url format.
export const toBase64Url = (data: string | Buffer) =>
	Buffer.isBuffer(data) ?
		data.toString('base64url')
	:	Buffer.from(data).toString('base64url')
