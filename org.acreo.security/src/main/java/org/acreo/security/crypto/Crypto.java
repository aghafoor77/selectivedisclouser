/*package org.acreo.security.crypto;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import org.acreo.common.exceptions.VeidblockException;
import org.acreo.security.crypto.CryptoStructure.ENCODING_DECODING_SCHEME;
import org.acreo.security.crypto.CryptoStructure.HASH_ALGO;

public class Crypto implements ICrypto {

	private CryptoPolicy encryptionSuite = new CryptoPolicy();
	private String password;
	public Crypto(){
		password = null;
		this.encryptionSuite = new CryptoPolicy ();
	}
	public Crypto(CryptoPolicy encryptionSuite){
		password = null;
		this.encryptionSuite = encryptionSuite;
	}
	public Crypto(String password){
		this.password = password;
	}
	
	public void setPassword(String password){
		this.password = password;
	}
	
	//@Override
	public byte[] encrypDB(String fieldValue) throws VeidblockException {
		Encryption idmsEncryption = new Encryption(this.encryptionSuite );
		return idmsEncryption.encrypDB(password, fieldValue);
	}

	//@Override
	public byte[] decryptDB(String encryptedFieldValue) throws VeidblockException {
		Encryption idmsEncryption = new Encryption(this.encryptionSuite );
		return idmsEncryption.decryptDB(password, encryptedFieldValue);
	}

	//@Override
	public byte[] encrypDB(byte[] fieldValue) throws VeidblockException {
		Encryption idmsEncryption = new Encryption(this.encryptionSuite );
		return idmsEncryption.encrypDB(password, fieldValue);
	}

	//@Override
	public byte[] decryptDB(byte[] encryptedFieldValue) throws VeidblockException {
		Encryption idmsEncryption = new Encryption(this.encryptionSuite );
		return idmsEncryption.decryptDB(password, encryptedFieldValue);
	}

	//@Override
	public byte[] generateFieldHash() {
		
		return null;
	}

	//@Override
	public byte[] verifyFieldHash(byte[] hash) {
		// TODO Auto-generated method stub
		return null;
	}

	//@Override
	public byte[] encrypt(byte[] data, ENCODING_DECODING_SCHEME encoding) {
		// TODO Auto-generated method stub
		return null;
	}

	//@Override
	public byte[] encrypt(byte[] data, String symmetricKey, ENCODING_DECODING_SCHEME encoding) {
		// TODO Auto-generated method stub
		return null;
	}

	//@Override
	public byte[] encrypt(byte[] data, byte[] symmetricKey, ENCODING_DECODING_SCHEME encoding) {
		// TODO Auto-generated method stub
		return null;
	}

	//@Override
	public byte[] encrypt(byte[] data, PublicKey publicKey, ENCODING_DECODING_SCHEME encoding) {
		// TODO Auto-generated method stub
		return null;
	}

	//@Override
	public byte[] encrypt(byte[] data, PrivateKey publicKey, ENCODING_DECODING_SCHEME encoding) {
		// TODO Auto-generated method stub
		return null;
	}

	//@Override
	public byte[] encrypt(byte[] data, Certificate certificate, ENCODING_DECODING_SCHEME encoding) {
		// TODO Auto-generated method stub
		return null;
	}

	//@Override
	public byte[] decrypt(String encryptedText, ENCODING_DECODING_SCHEME encoding) {
		// TODO Auto-generated method stub
		return null;
	}

	//@Override
	public byte[] decrypt(String encryptedText, String symmetricKey, ENCODING_DECODING_SCHEME encoding) {
		// TODO Auto-generated method stub
		return null;
	}

	//@Override
	public byte[] decrypt(String encryptedText, byte[] symmetricKey, ENCODING_DECODING_SCHEME encoding) {
		// TODO Auto-generated method stub
		return null;
	}

	//@Override
	public byte[] decrypt(String encryptedText, PublicKey publicKey, ENCODING_DECODING_SCHEME encoding) {
		// TODO Auto-generated method stub
		return null;
	}

	//@Override
	public byte[] decrypt(String encryptedText, PrivateKey publicKey, ENCODING_DECODING_SCHEME encoding) {
		// TODO Auto-generated method stub
		return null;
	}

	//@Override
	public byte[] decrypt(String encryptedText, Certificate certificate, ENCODING_DECODING_SCHEME encoding) {
		// TODO Auto-generated method stub
		return null;
	}

	//@Override
	public byte[] generateHash(byte[] data) throws VeidblockException {
		
		Hashing idmsHash = new Hashing(encryptionSuite);
		return idmsHash.generateHash(data);		
	}

	//@Override
	public boolean verifyHash(byte []oldHash, byte [] data) throws VeidblockException {
		Hashing idmsHash = new Hashing(encryptionSuite);
		if (idmsHash.verifyHash(oldHash, data)){
			return true;
		}
		return false;
	}

	//@Override
	public byte[] signPKCS7(byte[] data) {
		// TODO Auto-generated method stub
		return null;
	}

	//@Override
	public byte[] signPKCS7(String data) {
		// TODO Auto-generated method stub
		return null;
	}

	//@Override
	public byte[] verifySignature(byte[] pkcs7) {
		// TODO Auto-generated method stub
		return null;
	}

	//@Override
	public byte[] verifySignature(String pkcs7) {
		// TODO Auto-generated method stub
		return null;
	}

	
	//@Override
	public Certificate generateSelfSignedCertificate(Person person) {
		// TODO Auto-generated method stub
		return null;
	}

	//@Override
	public Certificate getSelfSignedCertificate(Person person) {
		// TODO Auto-generated method stub
		return null;
	}
}
*/