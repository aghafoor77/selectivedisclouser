package org.acreo.security.crypto;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.KeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.acreo.security.exceptions.VeidblockException;
import org.acreo.security.utils.CryptoIO;
import org.acreo.security.utils.JsonStorage;
import org.acreo.security.utils.PersonCredentials;
import org.acreo.security.utils.SGen;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.fasterxml.jackson.databind.ObjectMapper;

public class SecurityProperties {

	private CryptoPolicy cryptoPolicy = new CryptoPolicy();

	public SecurityProperties(CryptoPolicy cryptoPolicy ) {
		this.cryptoPolicy = cryptoPolicy;
	}

	public byte[] getDbKey(PersonCredentials personCredentials) throws VeidblockException {

		if (personCredentials == null) {
			throw new VeidblockException("Status.ERROR, ExceptionType.PERSON_CREDENTIALS_NOT_SPECIFIED");
		}

		String fetchedStoredKey = fetchProtectionKey("ssk");
		if (fetchedStoredKey == null) {
			throw new VeidblockException("Could not find DB key !");
		}

		byte keyToOpenKey[] = getNewProtectedKey(personCredentials.getPassword());

		return encryptDecrypt(keyToOpenKey, fetchedStoredKey.getBytes(), Cipher.DECRYPT_MODE);

	}

	public void setDbKey(PersonCredentials personCredentials) throws VeidblockException {

		SGen sGen = new SGen();
		byte keyToStore[] = getNewProtectedKey(new String(Base64.getEncoder().encode(sGen.genReandomNo(cryptoPolicy.getKeySize(), cryptoPolicy.getEncAlgorithm()))));
		if (keyToStore == null) {
			throw new VeidblockException("Key for Store is null !");
		}
		byte passwordBasedkey[] = getNewProtectedKey(personCredentials.getPassword());
		if (passwordBasedkey == null) {
			throw new VeidblockException("Problems when extending passowrd for creating keys !");
		}

		byte[] protectedkey = encryptDecrypt(passwordBasedkey, keyToStore, Cipher.ENCRYPT_MODE);
		if (protectedkey == null) {
			throw new VeidblockException("Problems when encrypting store key with password !");
		}
		storeProtectionKey(new String(protectedkey));
	}

	public String fetchProtectionKey(String key) throws VeidblockException {
		try {
			
			byte data[] = new CryptoIO().readData(cryptoPolicy.getSharedSecretArea());			
			String protectedFiledata = new String(data, "UTF-8");
			JsonStorage jsonStorage = null;
			ObjectMapper objectMapper = new ObjectMapper();
			jsonStorage = objectMapper.readValue(protectedFiledata, JsonStorage.class);
			if (jsonStorage.containsKey(key)) {
				String protectedData = (String) jsonStorage.get(key);
				return protectedData;
			} else {
				return null;
			}
		} catch (IOException e) {
			throw new VeidblockException(e);
		}
	}

	public void storeProtectionKey(String protectionKey) throws VeidblockException {
		JsonStorage jsonStorage = new JsonStorage();
		jsonStorage.put("ssk", protectionKey);
		ObjectMapper objectMapper = new ObjectMapper();
		try {
			String json = objectMapper.writeValueAsString(jsonStorage);
			if (!(new CryptoIO().writeData(cryptoPolicy.getSharedSecretArea(), json))) {
				throw new VeidblockException("Status.ERROR, ExceptionType.IOEXCEPTION");
			}

		} catch (IOException e) {
			throw new VeidblockException("Status.ERROR, ExceptionType.IOEXCEPTION");
		}
	}

	public byte[] getNewProtectedKey(String password) throws VeidblockException {
		try {
			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
			KeySpec spec = new PBEKeySpec(password.toCharArray(), cryptoPolicy.getSalt().getBytes(), 65536, 128);
			SecretKey tmp = factory.generateSecret(spec);
			SecretKey secret = new SecretKeySpec(tmp.getEncoded(), cryptoPolicy.getEncAlgorithm());
			return secret.getEncoded();
		} catch (Exception exp) {
			throw new VeidblockException("Status.ERROR, ExceptionType.PROTECTION_KEY_GEN_EXP");
		}
	}

	private byte[] encryptDecrypt(byte[] password, byte[] fieldValue, int mode) throws VeidblockException {

		try {
			Cipher cipher = Cipher.getInstance(cryptoPolicy.getCipherInstanceType());
			SecretKey secret = generateKey(password, cryptoPolicy.getEncAlgorithm());
			cipher.init(mode, secret, new IvParameterSpec(cryptoPolicy.getIv()));
			byte[] toCrypto = null;
			String strCiphertext = null;
			if (Cipher.DECRYPT_MODE == mode) {
				toCrypto = Base64.getDecoder().decode(fieldValue);
			} else {
				toCrypto = fieldValue;
			}
			byte[] ciphertext = cipher.doFinal(toCrypto);
			if (Cipher.ENCRYPT_MODE == mode) {
				strCiphertext  = new String(Base64.getEncoder().encode(ciphertext), "UTF-8");
				return strCiphertext.getBytes();
			} else {

				return ciphertext;
			}

		} catch (IOException | IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException
				| NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException e) {
			throw new VeidblockException(e);
		}
	}

	public SecretKey generateKey(byte[] storedKey, String algo) throws VeidblockException {
		try {
			SecretKey secret = new SecretKeySpec(storedKey, algo);
			return secret;
		} catch (Exception e) {
			throw new VeidblockException(e);
		}
	}

	public  byte[] generateSymmetricKey(String random) throws VeidblockException {
		try {
			SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
			KeySpec spec = new PBEKeySpec(random.toCharArray(), cryptoPolicy.getSalt().getBytes(), 65536, cryptoPolicy.getKeySize());
			SecretKey tmp = factory.generateSecret(spec);
			SecretKey secret = new SecretKeySpec(tmp.getEncoded(), cryptoPolicy.getEncAlgorithm());
			return secret.getEncoded();
		} catch (Exception exp) {
			throw new VeidblockException("Status.ERROR, ExceptionType.PROTECTION_KEY_GEN_EXP");
		}
	}
	
	public KeyPair generateRSAKeyPair(int keySize) throws Exception {
		new BouncyCastleProvider();
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(keySize);
		KeyPair pair = keyGen.generateKeyPair();
		return pair;
	}	
}