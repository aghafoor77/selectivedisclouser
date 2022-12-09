package org.acreo.veidblock.main;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;

import org.acreo.security.crypto.CryptoPolicy;
import org.acreo.security.utils.SGen;
import org.acreo.veidblock.JWSToken;
import org.acreo.veidblock.SsoManager;

public class JWSTokenTest {

	public static void main(String[] args) throws Exception {

		
		
		
		CryptoPolicy encryptionSuite = new CryptoPolicy();
		Calendar cal = Calendar.getInstance(); // creates calendar
		cal.setTime(new Date()); // sets calendar time/date
		cal.add(Calendar.HOUR_OF_DAY, 16); // adds one day

		// SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss z");
		// dateFormat.setTimeZone(TimeZone.getTimeZone("GMT"));
		SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
		System.out.println(dateFormat.format(cal.getTime()));

		String iss = "ISSUERPUBLICADDRESS";
		String sub = "SUBJECTPUBLICADDRESS";
		String scp = "issuer";
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);
		KeyPair kp = kpg.generateKeyPair(); // -----------------------------------------------
		JWSToken token = new SsoManager().generateSsoToken(kp.getPrivate(), kp.getPublic(), iss, sub, "1.0", scp, 8);
		System.out.println(token.toEncoded());
		String encoded = token.toEncoded();
		JWSToken jwt = new JWSToken(encoded);
		System.out.println(jwt.getPayload().toEncoded());
		System.out.println(jwt.getSignatureJWT().toEncoded());
		System.out.println(token.verify());

	}
	
	public static String addHours(int hours) {
		SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss");
		int cHour = new Date().getHours();
		System.out.println(cHour);
		int newHrs = cHour+8;
		System.out.println(newHrs);
		if(newHrs < 24) {
			Date date = new Date();
			date.setHours(newHrs);
			System.out.println(dateFormat.format(date));
		}
		
		
		
		return null;
	}
	
}
