import { utils, getPublicKeyAsync } from "@noble/ed25519";
import { randomBytes, createHash } from 'crypto';
global.crypto = {
	getRandomValues: function(buffer) {
		return randomBytes(buffer.length);
	},
	subtle: {
		digest: async function(algorithm, buffer) {
			if (algorithm !== 'SHA-512') {
				throw new Error(`Unsupported algorithm ${algorithm}`);
			}
			const hash = createHash('sha512');
			hash.update(Buffer.from(buffer));
			return Uint8Array.from(hash.digest());
		}
	}
};
module.exports = {
	generate: async function() {
		let privateKey = utils.randomPrivateKey();
		let publicKey = await getPublicKeyAsync(privateKey);

		privateKey = privateKey.toString("base64");
		publicKey = Buffer.from(publicKey).toString('base64');

		return {
			publicKey: publicKey
			privateKey: privateKey
		}
	}
};