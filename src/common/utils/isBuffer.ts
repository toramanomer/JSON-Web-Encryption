/**
 * Checks if a value is a Buffer
 */
export const isBuffer = (value: unknown): value is Buffer =>
	Buffer.isBuffer(value)
