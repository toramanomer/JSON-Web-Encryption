import { randomBytes } from 'node:crypto'

export const generateIV = (bytes: number) => randomBytes(bytes)
