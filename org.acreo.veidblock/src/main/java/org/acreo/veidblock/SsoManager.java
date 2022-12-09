package org.acreo.veidblock;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;

import org.acreo.security.crypto.CryptoPolicy;
import org.acreo.security.exceptions.VeidblockException;
import org.acreo.security.utils.SGen;
import org.acreo.veidblock.token.Header;
import org.acreo.veidblock.token.JWToken;
import org.acreo.veidblock.token.Payload;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * 
 * @author abdul.ghafoor@ri.se
 *
 */
public class SsoManager {

	private final Logger logger = LogManager.getLogger(JWTokenOperations.class);
	private String marker = "\t===> : ";
	private Header header = null;
	private Payload payload = null;

	/**
	 * 
	 * @param privateKey
	 * @param certificate
	 * @param jwToken
	 * @return object of valid JWToken
	 * @throws Exception
	 */
	public JWSToken generateSsoToken(PrivateKey privateKey, X509Certificate certificate, JWToken jwToken)
			throws Exception {
		JWTokenOperations jwTokenOperations = new JWTokenOperations();
		CryptoPolicy encryptionSuite = new CryptoPolicy();
		return new JWSToken(jwTokenOperations.signJWToken(jwToken, privateKey, certificate, encryptionSuite));
	}

	/**
	 * 
	 * @param privateKey
	 * @param publicKey
	 * @param jwToken
	 * @return Object of valid token
	 * @throws Exception
	 */
	public JWSToken generateSsoToken(PrivateKey privateKey, PublicKey publicKey, JWToken jwToken) throws Exception {
		JWTokenOperations jwTokenOperations = new JWTokenOperations();
		CryptoPolicy encryptionSuite = new CryptoPolicy();
		return new JWSToken(jwTokenOperations.signJWToken(jwToken, privateKey, publicKey, encryptionSuite));
	}
/**
 * 
 * @param privateKey
 * @param publicKey
 * @param iss : Issue 
 * @param sub : Holder (Subject)
 * @param ver : Version
 * @param scp: Scope (roles)
 * @param lifeHours
 * @return Object of valid token 
 * @throws Exception
 */
	public JWSToken generateSsoToken(PrivateKey privateKey, PublicKey publicKey, String iss, String sub, String ver,
			String scp, int lifeHours) throws Exception {
		JWTokenOperations jwTokenOperations = new JWTokenOperations();
		CryptoPolicy encryptionSuite = new CryptoPolicy();
		Calendar cal = Calendar.getInstance(); // creates calendar
		cal.setTime(new Date()); // sets calendar time/date
		// Setting expire date of token 
		cal.add(Calendar.HOUR_OF_DAY, lifeHours); // add time in hours
		SGen sGen = new SGen();
		String jti = sGen.generateId() + "";

		SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		//Crating payload and header 
		Payload payload = Payload.builder().iss(iss).sub(sub).ver(ver).exp(dateFormat.format((cal.getTime()))).scp(scp)
				.refreshToken("NOT-USED").jti(jti).build();
		Header header = Header.builder().alg("RSA.SHA-256").type("JWS").build();
		JWToken jwToken = new JWToken(header, payload);
		return new JWSToken(jwTokenOperations.signJWToken(jwToken, privateKey, publicKey, encryptionSuite));
	}

	/**
	 * 
	 * @param privateKey
	 * @param certificate
	 * @return return object of a valid JW Token
	 * @throws Exception
	 */
	public JWSToken generateSsoToken(PrivateKey privateKey, X509Certificate certificate) throws Exception {

		JWTokenOperations jwTokenOperations = new JWTokenOperations();

		if (header == null || payload == null) {
			throw new VeidblockException(new NullPointerException("Token header or payload is null !"));
		}

		JWToken jwTokenExt = new JWToken(header, payload);
		CryptoPolicy encryptionSuite = new CryptoPolicy();
		return new JWSToken(jwTokenOperations.signJWToken(jwTokenExt, privateKey, certificate, encryptionSuite));
	}

	public Header getHeader() {
		return header;
	}

	public void setHeader(Header header) {
		this.header = header;
	}

	public Payload getPayload() {
		return payload;
	}

	public void setPayload(Payload payload) {
		this.payload = payload;
	}
}