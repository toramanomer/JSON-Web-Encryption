import { diffieHellman, type KeyObject } from 'node:crypto'

export const computeAgreedKey = ({
	privateKey,
	publicKey
}: {
	privateKey: KeyObject
	publicKey: KeyObject
}) => diffieHellman({ privateKey, publicKey })
