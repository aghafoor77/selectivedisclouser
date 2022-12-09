package org.acreo.security;

import org.acreo.security.crypto.CryptoPolicy;
import org.acreo.security.crypto.PwdBasedEncryption;

public class CryptoTest {

	public static void main(String[] args) throws Exception {
		// TODO Auto-generated method stub
		//testPwdBasedEncryption ();
		et();
	}
	
	public static void testPwdBasedEncryption(){
		CryptoPolicy encryptionSuite = new CryptoPolicy();
		String password = "12345678";
		try {
			PwdBasedEncryption pwdBasedEncryption = new PwdBasedEncryption(/*encryptionSuite, password*/);
			System.out.println(new String(pwdBasedEncryption.decryptDB(pwdBasedEncryption.encrypDB("abdul".getBytes()))));
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	
	public static void et() throws Exception {
		
	}
	
	
	
}
