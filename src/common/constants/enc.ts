export const encHeaderParameterValues = Object.freeze({
	'A128CBC-HS256': 'A128CBC-HS256',
	'A192CBC-HS384': 'A192CBC-HS384',
	'A256CBC-HS512': 'A256CBC-HS512',
	'A128GCM': 'A128GCM',
	'A192GCM': 'A192GCM',
	'A256GCM': 'A256GCM'
})

export type EncHeaderParameterValues = keyof typeof encHeaderParameterValues

export const encHeaderParameters = Object.freeze({
	[encHeaderParameterValues['A128CBC-HS256']]: Object.freeze({
		aesAlg: 'aes-128-cbc',
		keyBytes: 32,
		encKeyBytes: 16,
		macKeyBytes: 16,
		hmacHashAlg: 'sha256',
		authTagBytes: 16,
		ivBytes: 16
	}),
	[encHeaderParameterValues['A192CBC-HS384']]: Object.freeze({
		aesAlg: 'aes-192-cbc',
		keyBytes: 48,
		encKeyBytes: 24,
		macKeyBytes: 24,
		hmacHashAlg: 'sha384',
		authTagBytes: 24,
		ivBytes: 16
	}),
	[encHeaderParameterValues['A256CBC-HS512']]: Object.freeze({
		aesAlg: 'aes-256-cbc',
		keyBytes: 64,
		encKeyBytes: 32,
		macKeyBytes: 32,
		hmacHashAlg: 'sha512',
		authTagBytes: 32,
		ivBytes: 16
	}),
	[encHeaderParameterValues['A128GCM']]: Object.freeze({
		aesAlg: 'aes-128-gcm',
		cekBytes: 16,
		ivBytes: 12,
		authTagBytes: 16
	}),
	[encHeaderParameterValues['A192GCM']]: Object.freeze({
		aesAlg: 'aes-192-gcm',
		cekBytes: 24,
		ivBytes: 12,
		authTagBytes: 16
	}),
	[encHeaderParameterValues['A256GCM']]: Object.freeze({
		aesAlg: 'aes-256-gcm',
		cekBytes: 32,
		ivBytes: 12,
		authTagBytes: 16
	})
})

export const cbcParams = Object.freeze({
	[encHeaderParameters['A128CBC-HS256'].aesAlg]:
		encHeaderParameters['A128CBC-HS256'],
	[encHeaderParameters['A192CBC-HS384'].aesAlg]:
		encHeaderParameters['A192CBC-HS384'],
	[encHeaderParameters['A256CBC-HS512'].aesAlg]:
		encHeaderParameters['A256CBC-HS512']
})

export const gcmParams = Object.freeze({
	[encHeaderParameters['A128GCM'].aesAlg]: encHeaderParameters['A128GCM'],
	[encHeaderParameters['A192GCM'].aesAlg]: encHeaderParameters['A192GCM'],
	[encHeaderParameters['A256GCM'].aesAlg]: encHeaderParameters['A256GCM']
})
