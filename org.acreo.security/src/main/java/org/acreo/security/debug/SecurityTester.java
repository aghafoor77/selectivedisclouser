/**
 * 
 */
package org.acreo.security.debug;

import java.io.IOException;

import org.acreo.security.certificate.CMSDelegator;
import org.acreo.security.certificate.CertificateSuite;
import org.acreo.security.exceptions.VeidblockException;
import org.acreo.security.utils.DistinguishName;

/**
 * @author aghafoor
 *
 */
public class SecurityTester {

	/**
	 * @param args
	 */
	public static void main(String[] args) {		
		
		new SecurityTester().createTopCertificate();
	}
	
	public void playWithBinary(){
		int no1 = (int)Math.pow((double)2, (double)0);
		int no2 = (int)Math.pow((double)2, (double)1);
		int no3 = (int)Math.pow((double)2, (double)2);
		
		double no = no1|no2|no3;
		System.out.println();
	}
	
	public void createTopCertificate() {

		String keyStoreCredentials = "12345678";
		CertificateSuite certificateSuite = new CertificateSuite("pki", 5);

		CMSDelegator pkiDelegator = new CMSDelegator(keyStoreCredentials, certificateSuite);
		new DisplayCertProps().listAllCertificate(certificateSuite);
		DistinguishName tca = null, ca = null;
		try {
			
			tca = DistinguishName.builder().name("TCA").email("tca@veidblock.se").country("SE").organization("RISE").organizationUnit("Acreo").build();
			pkiDelegator.generateTopCACert(tca);
			new DisplayCertProps().listAllCertificate(certificateSuite);
		} catch (VeidblockException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		try{
			ca = DistinguishName.builder().name("CA").email("ca@veidblock.se").country("SE").organization("RISE").organizationUnit("Acreo").build();
			//pkiDelegator.generateIntermediateCACert(tca, ca);
			new DisplayCertProps().listAllCertificate(certificateSuite);
		} catch (VeidblockException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		try{
			ca = DistinguishName.builder().name("CA").email("ca@veidblock.se").country("SE").organization("RISE").organizationUnit("Acreo").build();
			System.out.println(pkiDelegator.fetchPkiPemChain(ca));
			new DisplayCertProps().listAllCertificate(certificateSuite);
		} catch (VeidblockException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
