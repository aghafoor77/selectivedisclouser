package org.acreo.security.crypto;

import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.acreo.security.exceptions.VeidblockException;
import org.acreo.security.utils.PersonCredentials;

public class CryptoUtils {
	
	private CryptoPolicy cryptoPolicy = null;
	public CryptoUtils (CryptoPolicy cryptoPolicy){
		this.cryptoPolicy = cryptoPolicy ;
	}
	
	public SecretKey fetchDBSecretKey(String password) throws VeidblockException{
		SecurityProperties securityProperties = new SecurityProperties(cryptoPolicy);
		PersonCredentials personCredentials = new PersonCredentials();
		personCredentials.setPassword(password);
		byte [] key = securityProperties.getDbKey(personCredentials);
		return securityProperties.generateKey(key, cryptoPolicy.getEncAlgorithm());				
	}

	@SuppressWarnings("restriction")
	public byte[] encryptDecrypt(SecretKey secret, byte [] fieldValue, int mode) throws VeidblockException {
		try {
			Cipher cipher = Cipher.getInstance(cryptoPolicy.getCipherInstanceType());
			SecurityProperties securityProperties = new SecurityProperties(cryptoPolicy);
			cipher.init(mode, secret, new IvParameterSpec(cryptoPolicy.getIv()));
			byte[] toCrypto = null;
			String strCiphertext = null;
			if (Cipher.DECRYPT_MODE == mode) {
				toCrypto = Base64.getDecoder().decode(new String (fieldValue, "UTF-8"));
			} else {
				toCrypto = fieldValue;
			}
			byte[] ciphertext = cipher.doFinal(toCrypto);
			if (Cipher.ENCRYPT_MODE == mode) {
				strCiphertext = new String(Base64.getEncoder().encode(ciphertext), "UTF-8");
			} else {
				strCiphertext = new String(ciphertext);
			}
			
			return strCiphertext.getBytes();
			

		} catch (Exception e) {
			throw new VeidblockException(e);
		}

	}

	public byte[] encryptDecrypt(SecretKey secret, String fieldValue, int mode) throws VeidblockException {
		try {
			Cipher cipher = Cipher.getInstance(cryptoPolicy.getCipherInstanceType());
			cipher.init(mode, secret, new IvParameterSpec(cryptoPolicy.getIv()));
			byte[] toCrypto = null;
			String strCiphertext = null;
			if (Cipher.DECRYPT_MODE == mode) {
				toCrypto = Base64.getDecoder().decode(fieldValue);
			} else {
				toCrypto = fieldValue.getBytes();
			}
			byte[] ciphertext = cipher.doFinal(toCrypto);
			if (Cipher.ENCRYPT_MODE == mode) {
				strCiphertext  = new String(Base64.getEncoder().encode(ciphertext), "UTF-8");
				ciphertext = strCiphertext.getBytes("UTF-8"); 
			} 
			return ciphertext;

		} catch (Exception e) {
			throw new VeidblockException(e);
		}
	}
}
