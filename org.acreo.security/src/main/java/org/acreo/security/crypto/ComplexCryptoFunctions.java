package org.acreo.security.crypto;

import java.security.PrivateKey;
import java.security.PublicKey;

import org.acreo.security.crypto.CryptoStructure.ENCODING_DECODING_SCHEME;
import org.acreo.security.exceptions.VeidblockException;


public class ComplexCryptoFunctions {
	private CryptoPolicy cryptoPolicy;
	
	public ComplexCryptoFunctions (CryptoPolicy cryptoPolicy){
		this.cryptoPolicy= cryptoPolicy;		
	}
	
	public byte[] generateSignature(PrivateKey privateKey, byte [] data, ENCODING_DECODING_SCHEME scheme) throws VeidblockException{
		Hashing idmsHash = new Hashing(cryptoPolicy);
		Encryption idmsEncryption = new Encryption(cryptoPolicy);
		byte[] hashedValue = idmsHash.digestraw(data);
		
		if (hashedValue != null){
			return idmsEncryption.encrypt(privateKey, hashedValue, scheme);
		}
		else{
			return hashedValue;			
		}
	}
	public boolean verifySignature(PublicKey publicKey, byte [] data, byte[] signature, ENCODING_DECODING_SCHEME scheme) throws VeidblockException{
		
		Hashing idmsHash = new Hashing(cryptoPolicy);
		Encryption idmsEncryption = new Encryption(cryptoPolicy);
		byte[] hashedValue = idmsEncryption.decrypt(publicKey, signature, scheme);
		
		if (hashedValue != null){
			return idmsHash.verifyraw(hashedValue , data);
		}
		else{
			return false;			
		}		
	}
}