package org.acreo.veidblock;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

import org.acreo.security.crypto.ComplexCryptoFunctions;
import org.acreo.security.crypto.CryptoPolicy;
import org.acreo.security.crypto.CryptoStructure.ENCODING_DECODING_SCHEME;
import org.acreo.security.exceptions.VeidblockException;
import org.acreo.security.utils.PEMStream;
import org.acreo.veidblock.token.JWToken;
import org.acreo.veidblock.token.SignatureJWT;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * 
 * @author abdul.ghafoor@ri.se
 *
 */
public class JWTokenOperations {
	private final Logger logger = LogManager.getLogger(JWTokenOperations.class);
	private String marker = "\t===> : ";

	/**
	 * 
	 * @param jwToken
	 * @param privateKey
	 * @param x509certificate
	 * @param encryptionSuite
	 * @return object of newly created JWToken
	 * @throws VeidblockException
	 */
	public JWToken signJWToken(JWToken jwToken, PrivateKey privateKey, X509Certificate x509certificate,
			CryptoPolicy encryptionSuite) throws VeidblockException {
		try {
			ComplexCryptoFunctions complexCrypto = new ComplexCryptoFunctions(encryptionSuite);
			// generating signature using private key with BASE 64 encoded
			byte[] siganture = complexCrypto.generateSignature(privateKey, jwToken.toEncoded4Signature().getBytes(),
					ENCODING_DECODING_SCHEME.NONE);
			if (siganture != null) {
				// Setting signature object in JWToken with public key
				SignatureJWT signatureJWT = SignatureJWT.builder().signature(siganture)
						.publickey(x509certificate.getPublicKey().getEncoded()).build();
				jwToken.setSignatureJWT(signatureJWT);
				return jwToken;
			}
			logger.error(marker + " Problems when creating JWS Token [1]!");
			throw new VeidblockException("Problems when creating JWS Token !");
		} catch (Exception exp) {
			logger.error(marker + " Problems when creating JWS Token [1]!");
			logger.error(marker + exp.getMessage());
			throw new VeidblockException(exp);
		}
	}

	/**
	 * Generating signature with customized Crypto Policy
	 * 
	 * @param jwToken
	 * @param privateKey
	 * @param publicKey
	 * @param encryptionSuite
	 * @return object of JWToken
	 * @throws VeidblockException
	 */
	public JWToken signJWToken(JWToken jwToken, PrivateKey privateKey, PublicKey publicKey,
			CryptoPolicy encryptionSuite) throws VeidblockException {
		try {
			ComplexCryptoFunctions complexCrypto = new ComplexCryptoFunctions(encryptionSuite);
			// generating signature using private key with BASE 64 encoded
			byte[] status = complexCrypto.generateSignature(privateKey, jwToken.toEncoded4Signature().getBytes(),
					ENCODING_DECODING_SCHEME.NONE);
			if (status != null) {
				SignatureJWT signatureJWT = SignatureJWT.builder().signature(status).publickey(publicKey.getEncoded())
						.build();
				// Setting signature object in JWToken with public key
				jwToken.setSignatureJWT(signatureJWT);
				return jwToken;
			}
			logger.error(marker + " Problems when creating JWS Token [1]!");
			throw new VeidblockException("Problems when creating JWS Token [2]!");
		} catch (Exception exp) {
			logger.error(marker + " Problems when creating JWS Token [2]!");
			logger.error(marker + exp.getMessage());
			throw new VeidblockException(exp);
		}
	}

	/**
	 * To verify signature using externally provided public key
	 * 
	 * @param jwToken
	 * @param x509certificate
	 * @return true or false
	 * @throws VeidblockException
	 */
	public boolean verifyJWToken(JWToken jwToken, X509Certificate x509certificate) throws VeidblockException {
		// date validation
		CryptoPolicy encryptionSuite = new CryptoPolicy();
		try {
			ComplexCryptoFunctions complexCrypto = new ComplexCryptoFunctions(encryptionSuite);
			// Verifying signature
			boolean status = complexCrypto.verifySignature(x509certificate.getPublicKey(),
					jwToken.toEncoded4Signature().getBytes(), jwToken.signatureJWT.getSignature(),
					ENCODING_DECODING_SCHEME.NONE);
			return status;
		} catch (Exception exp) {
			logger.error(
					marker + " Problems when veryfying JWS Token using external public key [online-verification]!");
			logger.error(marker + exp.getMessage());
			throw new VeidblockException(exp);
		}
	}

	/**
	 * To verify signature using stored public key in the JWS Token
	 * 
	 * @param jwToken
	 * @return
	 * @throws VeidblockException
	 */
	public boolean verifyJWToken(JWToken jwToken) throws VeidblockException {
		// date validation
		checkExpiryDate(jwToken.getPayload().getExp());
		// checkStartDate(jwToken.getPayload().getExp());
		CryptoPolicy encryptionSuite = new CryptoPolicy();

		try {
			ComplexCryptoFunctions complexCrypto = new ComplexCryptoFunctions(encryptionSuite);
			// Verifying signature
			byte[] pubKey = jwToken.getSignatureJWT().getPublickey();
			PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(pubKey));

			boolean status = complexCrypto.verifySignature(publicKey, jwToken.toEncoded4Signature().getBytes(),
					jwToken.signatureJWT.getSignature(), ENCODING_DECODING_SCHEME.NONE);
			return status;
		} catch (Exception exp) {
			logger.error(marker + " Problems when veryfying JWS Token [offline-verification]!");
			logger.error(marker + exp.getMessage());
			throw new VeidblockException(exp);
		}
	}

	/**
	 * 
	 * @param endDateStr
	 * @return true or false (if date is expired)
	 * @throws VeidblockException
	 */
	private boolean checkExpiryDate(String endDateStr) throws VeidblockException {

		Date theExpiryDate = null;
		SimpleDateFormat sdf = null;

		try {
			sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.ENGLISH);
			theExpiryDate = sdf.parse(endDateStr);
		} catch (Exception exp) {
			throw new VeidblockException("JWS Toekn expired - !");
		}

		Date currentDateTime = new Date();

		boolean before = currentDateTime.before(theExpiryDate);

		if (before) {
			return true;
		} else {
			logger.error(marker + " Session expired !");
			throw new VeidblockException("Error validating access token: Session has expired on " + endDateStr
					+ ". The current time is " + sdf.format(currentDateTime) + " !");
		}
	}

	/**
	 * 
	 * @param startDateStr
	 * @return true or false (If token's start date is after current date)
	 * @throws VeidblockException
	 *//*
		 * private boolean checkStartDate(String startDateStr) throws VeidblockException
		 * {
		 * 
		 * Date theStartDate = null; SimpleDateFormat sdf = null;
		 * 
		 * try { sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.ENGLISH);
		 * theStartDate = sdf.parse(startDateStr); } catch (Exception exp) { throw new
		 * VeidblockException("JWS Toekn expired !"); }
		 * 
		 * Date currentDateTime = new Date();
		 * 
		 * boolean before = currentDateTime.after(theStartDate);
		 * 
		 * if (before) { return true; } else { logger.error(marker +
		 * " JWS start date is not reached yet !"); throw new
		 * VeidblockException("Error validating access token: Session has expired on " +
		 * startDateStr + ". The current time is " + sdf.format(currentDateTime) +
		 * " !"); } }
		 */
}
