package org.acreo.security.crypto;

import java.io.File;

import org.acreo.security.crypto.CryptoStructure.ENCODING_DECODING_SCHEME;
import org.acreo.security.crypto.CryptoStructure.HASH_ALGO;

public class CryptoPolicy {
	private  String cipherInstanceType = "AES/CBC/PKCS5Padding";
	private String rSAEncryptionScheme = "RSA/ECB/PKCS1Padding";
	private String secretKeyInstanceType = "PBKDF2WithHmacSHA256";	
	private String encAlgorithm = "AES";
	private int keySize = 128;
	private String salt = "feacbc02a3a697b0";
	private byte [] iv={1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1};
	private HASH_ALGO hashAlgorithm = HASH_ALGO.SHA3_256;
	private ENCODING_DECODING_SCHEME hashEncoding = ENCODING_DECODING_SCHEME.NONE;
	private String sharedSecretArea = "id2.str";
	
	public CryptoPolicy(){
		String homeDir = System.getProperty("user.home");
		File dir = new File(homeDir + File.separator + "veidblock_RT");
		if (!dir.exists())
			dir.mkdirs();
		sharedSecretArea = dir.getAbsolutePath()+File.separator+sharedSecretArea;
	}	
	
	public String getCipherInstanceType() {
		return cipherInstanceType;
	}
	public void setCipherInstanceType(String cipherInstanceType) {
		this.cipherInstanceType = cipherInstanceType;
	}
	public String getrSAEncryptionScheme() {
		return rSAEncryptionScheme;
	}
	public void setrSAEncryptionScheme(String rSAEncryptionScheme) {
		this.rSAEncryptionScheme = rSAEncryptionScheme;
	}
	public String getSecretKeyInstanceType() {
		return secretKeyInstanceType;
	}
	public void setSecretKeyInstanceType(String secretKeyInstanceType) {
		this.secretKeyInstanceType = secretKeyInstanceType;
	}
	public String getEncAlgorithm() {
		return encAlgorithm;
	}
	public void setEncAlgorithm(String encAlgorithm) {
		this.encAlgorithm = encAlgorithm;
	}
	public int getKeySize() {
		return keySize;
	}
	public void setKeySize(int keySize) {
		this.keySize = keySize;
	}
	public String getSalt() {
		return salt;
	}
	public void setSalt(String salt) {
		this.salt = salt;
	}
	public byte[] getIv() {
		return iv;
	}
	public void setIv(byte[] iv) {
		this.iv = iv;
	}
	public HASH_ALGO getHashAlgorithm() {
		return hashAlgorithm;
	}
	public void setHashAlgorithm(HASH_ALGO hashAlgorithm) {
		this.hashAlgorithm = hashAlgorithm;
	}
	public ENCODING_DECODING_SCHEME getHashEncoding() {
		return hashEncoding;
	}
	public void setHashEncoding(ENCODING_DECODING_SCHEME hashEncoding) {
		this.hashEncoding = hashEncoding;
	}
	public String getSharedSecretArea() {
		return sharedSecretArea;
	}
	public void setSharedSecretArea(String sharedSecretArea) {
		this.sharedSecretArea = sharedSecretArea;
	}
}
