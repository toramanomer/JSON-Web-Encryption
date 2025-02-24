export const algHeaderParameters = Object.freeze({
	// Key Management Mode: Key Wrapping
	'A128KW': 'A128KW',
	'A192KW': 'A192KW',
	'A256KW': 'A256KW',

	// Key Management Mode: Key Wrapping
	'A128GCMKW': 'A128GCMKW',
	'A192GCMKW': 'A192GCMKW',
	'A256GCMKW': 'A256GCMKW',

	// Key Management Mode: Key Wrapping
	'PBES2-HS256+A128KW': 'PBES2-HS256+A128KW',
	'PBES2-HS384+A192KW': 'PBES2-HS384+A192KW',
	'PBES2-HS512+A256KW': 'PBES2-HS512+A256KW',

	// Key Management Mode: Key Encryption
	'RSA-OAEP': 'RSA-OAEP',
	'RSA-OAEP-256': 'RSA-OAEP-256',

	// Key Management Mode: Key Agreement with Key Wrapping
	'ECDH-ES+A128KW': 'ECDH-ES+A128KW',
	'ECDH-ES+A192KW': 'ECDH-ES+A192KW',
	'ECDH-ES+A256KW': 'ECDH-ES+A256KW',

	// Key Management Mode: Direct Encryption
	'dir': 'dir',

	// Key Management Mode: Direct Key Management
	'ECDH-ES': 'ECDH-ES'
})

export type AlgHeaderParameter = keyof typeof algHeaderParameters
