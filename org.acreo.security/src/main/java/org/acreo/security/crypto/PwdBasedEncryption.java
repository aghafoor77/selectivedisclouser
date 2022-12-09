package org.acreo.security.crypto;

import java.io.File;

import org.acreo.security.exceptions.VeidblockException;
import org.acreo.security.utils.PersonCredentials;

public class PwdBasedEncryption {
	
	private CryptoPolicy cryptoPolicy= null;
	private String password = null;
	
	public PwdBasedEncryption() throws Exception{
		this.password = "H;1E:3f_df!-";
		this.cryptoPolicy = new CryptoPolicy();
		
		SecurityProperties securityProperties = new SecurityProperties(cryptoPolicy);
		if(! new File(cryptoPolicy.getSharedSecretArea()).exists()){
			PersonCredentials personCredentials = new PersonCredentials();
			personCredentials.setPassword(this.password);
			securityProperties.setDbKey(personCredentials); 
		}
	}
	
	public byte[] encrypDB(String fieldValue) throws VeidblockException {
		Encryption encryption = new Encryption(this.cryptoPolicy);
		return encryption.encrypDB(password, fieldValue);
	}

	public byte[] decryptDB(String encryptedFieldValue) throws VeidblockException {
		Encryption idmsEncryption = new Encryption(this.cryptoPolicy);
		return idmsEncryption.decryptDB(password, encryptedFieldValue);
	}

	public byte[] encrypDB(byte[] fieldValue) throws VeidblockException {
		Encryption idmsEncryption = new Encryption(this.cryptoPolicy);
		return idmsEncryption.encrypDB(password, fieldValue);
	}

	public byte[] decryptDB(byte[] encryptedFieldValue) throws VeidblockException {
		Encryption idmsEncryption = new Encryption(this.cryptoPolicy);
		return idmsEncryption.decryptDB(password, encryptedFieldValue);
	}
}
