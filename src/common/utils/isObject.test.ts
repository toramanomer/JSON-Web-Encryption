import { describe, it, expect } from 'vitest'
import { isObject } from './isObject.js'

describe('isObject', () => {
	it.each([
		{ value: null, expected: false },
		{ value: undefined, expected: false },
		{ value: [], expected: false },
		{ value: {}, expected: true }
	])('must return $expected when value is $value', ({ value, expected }) => {
		expect(isObject(value)).toBe(expected)
	})
})
