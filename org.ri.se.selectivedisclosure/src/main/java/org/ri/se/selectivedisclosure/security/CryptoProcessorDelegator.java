package org.ri.se.selectivedisclosure.security;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Objects;

import org.acreo.security.crypto.CryptoPolicy;
import org.acreo.security.crypto.CryptoStructure.ENCODING_DECODING_SCHEME;
import org.acreo.security.crypto.CryptoStructure.HASH_ALGO;
import org.acreo.security.crypto.Encryption;
import org.acreo.security.crypto.Hashing;
import org.acreo.security.crypto.SecurityProperties;
import org.acreo.security.exceptions.VeidblockException;
import org.acreo.security.utils.SGen;



public class CryptoProcessorDelegator {

	public CryptoProcessorDelegator() {

	}

	public byte[] encrypt(byte key[], ENCODING_DECODING_SCHEME encoding, SecurityContext securityContext, byte[] input)
			throws Exception {
		CryptoPolicy cryptoPolicy = createCryptoPolicy(securityContext);
		Encryption encryption = new Encryption(cryptoPolicy);
		byte[] output = encryption.encrypt(key, input, encoding);
		return output;
	}

	public byte[] decrypt(byte key[], ENCODING_DECODING_SCHEME encoding, SecurityContext securityContext, byte[] input)
			throws Exception {
		CryptoPolicy cryptoPolicy = createCryptoPolicy(securityContext);
		Encryption encryption = new Encryption(cryptoPolicy);
		
		
		byte[] output = encryption.decrypt(key, input, encoding);
		
		return output;
	}

	public byte[] generateSymmetrickey(SecurityContext securityContext) throws VeidblockException {
		CryptoPolicy cryptoPolicy = createCryptoPolicy(securityContext);
		SecurityProperties securityProperties = new SecurityProperties(cryptoPolicy);
		byte key[] = securityProperties.generateSymmetricKey(new SGen().nextHexString(32));
		return key;
	}

	private CryptoPolicy createCryptoPolicy(SecurityContext securityContext) throws VeidblockException {

		CryptoPolicy cryptoPolicy = new CryptoPolicy();
		if (Objects.isNull(securityContext)) {
			return cryptoPolicy;
		}
		switch (securityContext) {
		case DES:
			byte iv[] = { 1, 2, 3, 4, 5, 6, 7, 8 };
			cryptoPolicy.setKeySize(64);
			cryptoPolicy.setEncAlgorithm("DES");
			cryptoPolicy.setCipherInstanceType("DES/CBC/PKCS5Padding");
			cryptoPolicy.setIv(iv);
			return cryptoPolicy;

		case AES128:
			byte iv128[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
			cryptoPolicy.setKeySize(128);
			cryptoPolicy.setEncAlgorithm("AES");
			cryptoPolicy.setCipherInstanceType("AES/CBC/PKCS5Padding");
			cryptoPolicy.setIv(iv128);
			return cryptoPolicy;
		case AES192:
			byte iv192[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
			cryptoPolicy.setKeySize(192);
			cryptoPolicy.setEncAlgorithm("AES");
			cryptoPolicy.setCipherInstanceType("AES/CBC/PKCS5Padding");
			cryptoPolicy.setIv(iv192);
			return cryptoPolicy;
		case AES256:
			byte iv256[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
			cryptoPolicy.setKeySize(256);
			cryptoPolicy.setEncAlgorithm("AES");
			cryptoPolicy.setCipherInstanceType("AES/CBC/PKCS5Padding");
			cryptoPolicy.setIv(iv256);
			return cryptoPolicy;
		case PRIVACY:
			throw new VeidblockException("Coming soon. Privacy security context not implemented yet !");

		default:
			throw new VeidblockException("Could not find security context '" + securityContext.value() + "'");

		}
	}

	public byte[] encrypt(PublicKey publicKey, ENCODING_DECODING_SCHEME encoding, SecurityContext securityContext,
			byte[] input) throws Exception {
		CryptoPolicy cryptoPolicy = createCryptoPolicy(securityContext);
		Encryption encryption = new Encryption(cryptoPolicy);
		byte[] output = encryption.encrypt(publicKey, input, encoding);
		return output;
	}

	public byte[] decrypt(PrivateKey privateKey, ENCODING_DECODING_SCHEME encoding, SecurityContext securityContext,
			byte[] input) throws Exception {
		CryptoPolicy cryptoPolicy = createCryptoPolicy(securityContext);
		Encryption encryption = new Encryption(cryptoPolicy);
		byte[] output = encryption.decrypt(privateKey, input, encoding);
		return output;
	}

	public byte[] encrypt(PrivateKey privateKey, ENCODING_DECODING_SCHEME encoding, SecurityContext securityContext,
			byte[] input) throws Exception {
		CryptoPolicy cryptoPolicy = createCryptoPolicy(securityContext);
		Encryption encryption = new Encryption(cryptoPolicy);
		byte[] output = encryption.encrypt(privateKey, input, encoding);
		return output;
	}

	public byte[] decrypt(PublicKey publicKey, ENCODING_DECODING_SCHEME encoding, SecurityContext securityContext,
			byte[] input) throws Exception {
		CryptoPolicy cryptoPolicy = createCryptoPolicy(securityContext);
		Encryption encryption = new Encryption(cryptoPolicy);
		byte[] output = encryption.decrypt(publicKey, input, encoding);
		return output;
	}

	public KeyPair generateRSAKeyPair(int keySize) throws Exception {
		return new SecurityProperties(null).generateRSAKeyPair(keySize);
	}

	public byte[] digest(byte data[]) throws Exception {
		CryptoPolicy cryptoPolicy = new CryptoPolicy();
		cryptoPolicy.setHashAlgorithm(HASH_ALGO.SHA3_256);
		cryptoPolicy.setHashEncoding(ENCODING_DECODING_SCHEME.HEX);
		Hashing hashing = new Hashing(cryptoPolicy);
		try {
			return hashing.digestEncoded(data);
		} catch (Exception e) {
			throw new Exception(e);
		}
	}

	public boolean verify(byte[] data, byte [] digest) throws Exception {
		CryptoPolicy cryptoPolicy = new CryptoPolicy();
		cryptoPolicy.setHashAlgorithm(HASH_ALGO.SHA3_256);
		cryptoPolicy.setHashEncoding(ENCODING_DECODING_SCHEME.HEX);
		Hashing hashing = new Hashing(cryptoPolicy);
		try {
			return  hashing.verifyEncoded(digest, data);
		} catch (Exception e) {
			throw new Exception(e);
		}
	}

}
