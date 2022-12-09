package org.acreo.security.crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import org.acreo.security.crypto.CryptoStructure.ENCODING_DECODING_SCHEME;
import org.acreo.security.exceptions.VeidblockException;
import org.apache.commons.codec.binary.Hex;

public class Hashing {
	
	private CryptoPolicy cryptoPolicy = new CryptoPolicy();
	private Hashing (){
		
	}
	public Hashing(CryptoPolicy cryptoPolicy ){
		this.cryptoPolicy = cryptoPolicy;
	}
	
	public byte [] digestraw(byte value[]) throws VeidblockException{
		try {
	        MessageDigest digest = MessageDigest.getInstance(cryptoPolicy.getHashAlgorithm().value());
	        return digest.digest(value);	        
	    } catch (NoSuchAlgorithmException exp) {
	    	throw new VeidblockException(exp);
	    }
	}
	
	public boolean verifyraw(byte [] oldhash, byte value[]) throws VeidblockException{
		byte hashed [] = digestraw(value);
		return MessageDigest.isEqual(oldhash, hashed);
	}
	
	public byte [] digestEncoded(byte value[]) throws VeidblockException{
		try {
	        MessageDigest digest = MessageDigest.getInstance(cryptoPolicy.getHashAlgorithm().value());
	        
	        return performEncoding(digest.digest(value), cryptoPolicy.getHashEncoding());	        
	    } catch (NoSuchAlgorithmException exp) {
	    	throw new VeidblockException(exp);
	    }
	}
	
	public boolean verifyEncoded(byte [] oldhash, byte value[]) throws Exception{
		byte []oldDigect = performDecoding(oldhash, cryptoPolicy.getHashEncoding());
		byte hashed [] = digestraw(value);
		return MessageDigest.isEqual(oldDigect, hashed);
	}
	
	private byte[] performEncoding(byte[] data, ENCODING_DECODING_SCHEME encoding) {
		switch (encoding) {
		case BASE64:
			return Base64.getEncoder().encode(data);
		case HEX:
			return new String(Hex.encodeHex(data)).getBytes();
		case NONE:
			return data;

		}
		return data;
	}

	private byte[] performDecoding(byte[] data, ENCODING_DECODING_SCHEME encoding) throws Exception {
		switch (encoding) {
		case BASE64:
			return Base64.getDecoder().decode(data);
		case HEX:
			return Hex.decodeHex(new String(data).toCharArray());
		case NONE:
			return data;

		}
		return data;
	}
	
	
}
