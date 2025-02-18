/**
 * Checks if a value is an object and not array or null
 */
export const isObject = (value: unknown): value is Record<string, unknown> =>
	!!value && typeof value === 'object' && !Array.isArray(value)
