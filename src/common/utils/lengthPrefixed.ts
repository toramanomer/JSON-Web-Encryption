import { Buffer } from 'node:buffer'

export const lengthPrefixed = (data: Buffer) => {
	const dataLength = Buffer.alloc(4)
	dataLength.writeUint32BE(data.length)
	return Buffer.concat([dataLength, data])
}
