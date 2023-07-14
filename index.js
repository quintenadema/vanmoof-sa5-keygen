const crypto = require('crypto');

global.crypto = {
	getRandomValues: function(buffer) {
		return crypto.randomBytes(buffer.length);
	},
	subtle: {
		digest: async function(algorithm, buffer) {
			if (algorithm !== 'SHA-512') {
				throw new Error(`Unsupported algorithm ${algorithm}`);
			}
			const hash = crypto.createHash('sha512');
			hash.update(Buffer.from(buffer));
			return Uint8Array.from(hash.digest());
		}
	}
};

let utils, getPublicKeyAsync;

async function initialize() {
	const ed25519 = await import('@noble/ed25519');
	utils = ed25519.utils;
	getPublicKeyAsync = ed25519.getPublicKeyAsync;
}

module.exports = {
	generate: async function() {
		if (!utils || !getPublicKeyAsync) {
			await initialize();
		}
		let privateKey = utils.randomPrivateKey();
		let publicKey = await getPublicKeyAsync(privateKey);

		privateKey = privateKey.toString("base64");
		publicKey = Buffer.from(publicKey).toString('base64');

		return {
			publicKey: publicKey,
			privateKey: privateKey
		}
	}
};
