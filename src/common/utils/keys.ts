/**
 * Extracts the keys of an object as a strongly typed array.
 */
export const keys = <Key extends string>(record: Record<Key, unknown>) =>
	Object.keys(record) as Key[]
