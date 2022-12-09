package org.ri.se.selectivedisclosure.security;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.acreo.security.crypto.CryptoStructure.ENCODING_DECODING_SCHEME;



/**
 * 
 * @author Abdul Ghafoor, abdul.ghafoor@ri.se
 * @implNote : This class implementa various functions required for protection
 *           (encryption and decryption) of data.
 *
 */
public class CryptoProcessor implements ICryptoProcessor {

	

	


	
	/**
	 * This method generates symmetric key based on the information provided in the
	 * SecurityContext.
	 * 
	 * @param SecurityContext: Used to identify symmetric key algorithm
	 * @return byte[] return symmetric key in bytes.
	 * 
	 */
	public byte[] generateSymmetrickey(SecurityContext securityContext) throws Exception {
		return new CryptoProcessorDelegator().generateSymmetrickey(securityContext);
	}

	/**
	 * This method generates key pair .
	 * 
	 * @param size: size of the asymmetric key
	 * @return byte[] returns keypair.
	 * 
	 */
	public KeyPair generateRSAKeyPair(int keySize) throws Exception {
		return new CryptoProcessorDelegator().generateRSAKeyPair(keySize);
	}

	
	

	

	/**
	 * 
	 * @param publicKey : public key used for encryption
	 * @param input     : input data for encryption
	 * @param encoding  : used to define encoding scheme
	 * @return : encrypted data in bytes array
	 * @throws Exception
	 */
	public byte[] encrypt(PublicKey publicKey, byte[] input, ENCODING_DECODING_SCHEME encoding) throws Exception {
		return new CryptoProcessorDelegator().encrypt(publicKey, encoding, null, input);
	}

	/**
	 * 
	 * @param PrivateKey : PrivateKey used for decryption
	 * @param input      : input data for decryption
	 * @param encoding   : used to define encoding scheme
	 * @return : encrypted data in bytes array
	 * @throws Exception
	 */
	public byte[] decrypt(PrivateKey privateKey, byte[] input, ENCODING_DECODING_SCHEME encoding) throws Exception {
		return new CryptoProcessorDelegator().decrypt(privateKey, encoding, null, input);
	}

	/**
	 * 
	 * @param PrivateKey : PrivateKey used for encryption
	 * @param input      : input data for encryption
	 * @param encoding   : used to define encoding scheme
	 * @return : encrypted data in bytes array
	 * @throws Exception
	 */
	public byte[] encrypt(PrivateKey privateKey, byte[] input, ENCODING_DECODING_SCHEME encoding) throws Exception {
		return new CryptoProcessorDelegator().encrypt(privateKey, encoding, null, input);
	}

	/**
	 * 
	 * @param PublicKey : PublicKey used for decryption
	 * @param input     : input data for decryption
	 * @param encoding  : used to define encoding scheme
	 * @return : encrypted data in bytes array
	 * @throws Exception
	 */
	public byte[] decrypt(PublicKey publicKey, byte[] input, ENCODING_DECODING_SCHEME encoding) throws Exception {
		return new CryptoProcessorDelegator().decrypt(publicKey, encoding, null, input);
	}

	public byte[] digest(byte data[]) throws Exception {
		return new CryptoProcessorDelegator().digest(data);
	}

	public boolean verify(byte[] data, byte[] digest) throws Exception {
		return new CryptoProcessorDelegator().verify(data, digest);
	}

	public byte[] encrypt(byte[] key, ENCODING_DECODING_SCHEME encoding, SecurityContext securityContext, byte data[])
			throws Exception {
		CryptoProcessorDelegator cryptoProcessorDelegator = new CryptoProcessorDelegator();
		try {
			byte output[] = cryptoProcessorDelegator.encrypt(key, encoding, securityContext, data);
			return output;
		} catch (Exception e) {
			throw new Exception(e);
		}

	}

	public byte[] decrypt(byte[] key, ENCODING_DECODING_SCHEME encoding, SecurityContext securityContext, byte data[])
			throws Exception {
		CryptoProcessorDelegator cryptoProcessorDelegator = new CryptoProcessorDelegator();
		try {
			byte output[] = cryptoProcessorDelegator.decrypt(key, encoding, securityContext, data);
			return output;
		} catch (Exception e) {
			throw new Exception(e);
		}

	}

}