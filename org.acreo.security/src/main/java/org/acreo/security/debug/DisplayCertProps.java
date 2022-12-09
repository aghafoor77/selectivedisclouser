package org.acreo.security.debug;

import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.acreo.security.certificate.CertificateSuite;
import org.acreo.security.exceptions.VeidblockException;
import org.acreo.security.utils.StoreHandling;

public class DisplayCertProps {

	public void displayX509Certificate(X509Certificate x509certificate) {
		try {
			CertificateFactory certificatefactory = CertificateFactory.getInstance("X.509");
			System.out.println("---Certificate---");
			System.out.println("type = " + x509certificate.getType());
			System.out.println("version = " + x509certificate.getVersion());
			System.out.println("subject = " + x509certificate.getSubjectDN().getName());
			System.out.println("valid from = " + x509certificate.getNotBefore());
			System.out.println("valid to = " + x509certificate.getNotAfter());
			System.out.println("serial number = " + x509certificate.getSerialNumber().toString(16));
			System.out.println("issuer = " + x509certificate.getIssuerDN().getName());
			System.out.println("signing algorithm = " + x509certificate.getSigAlgName());
			System.out.println("public key algorithm = " + x509certificate.getPublicKey().getAlgorithm());
			
			/*System.out.println(
					"KeyUsage = " + pkiUtil.extractKeyUsage(pkiUtil.getKeyUsage(x509certificate.getKeyUsage())));*/
			// Next, let's print out information about the extensions.
			System.out.println("---Extensions---");
			Set setCritical = x509certificate.getCriticalExtensionOIDs();
			if (setCritical != null && setCritical.isEmpty() == false)
				for (Iterator iterator = setCritical.iterator(); iterator.hasNext();)
					System.out.println(iterator.next().toString() + " *critical*");
			Set setNonCritical = x509certificate.getNonCriticalExtensionOIDs();
			if (setNonCritical != null && setNonCritical.isEmpty() == false)
				for (Iterator iterator = setNonCritical.iterator(); iterator.hasNext();)
					System.out.println(iterator.next().toString());
			// We're done.
			System.out.println("---");
			// Close the file.

		} catch (Exception exception) {
			exception.printStackTrace();
		}

	}

	public void displayX509Certificate(X509Certificate x509certificates[]) {

		if (x509certificates == null) {
			System.out.println("Certificate list is empty !");
		}
		for (int i = 0; i < x509certificates.length; i++) {
			X509Certificate x509certificate = x509certificates[i];
			try {
				CertificateFactory certificatefactory = CertificateFactory.getInstance("X.509");
				System.out.println("---Certificate---");
				System.out.println("type = " + x509certificate.getType());
				System.out.println("version = " + x509certificate.getVersion());
				System.out.println("subject = " + x509certificate.getSubjectDN().getName());
				System.out.println("valid from = " + x509certificate.getNotBefore());
				System.out.println("valid to = " + x509certificate.getNotAfter());
				System.out.println("serial number = " + x509certificate.getSerialNumber().toString(16));
				System.out.println("issuer = " + x509certificate.getIssuerDN().getName());
				System.out.println("signing algorithm = " + x509certificate.getSigAlgName());
				System.out.println("public key algorithm = " + x509certificate.getPublicKey().getAlgorithm());
				
				/*System.out.println(
						"KeyUsage = " + pkiUtil.extractKeyUsage(pkiUtil.getKeyUsage(x509certificate.getKeyUsage())));*/
				// Next, let's print out information about the extensions.
				System.out.println("---Extensions---");
				Set setCritical = x509certificate.getCriticalExtensionOIDs();
				if (setCritical != null && setCritical.isEmpty() == false)
					for (Iterator iterator = setCritical.iterator(); iterator.hasNext();)
						System.out.println(iterator.next().toString() + " *critical*");
				Set setNonCritical = x509certificate.getNonCriticalExtensionOIDs();
				if (setNonCritical != null && setNonCritical.isEmpty() == false)
					for (Iterator iterator = setNonCritical.iterator(); iterator.hasNext();)
						System.out.println(iterator.next().toString());
				// We're done.
				System.out.println("---");
				// Close the file.

			} catch (Exception exception) {
				exception.printStackTrace();
			}
		}
	}
	public void listAllCertificate(CertificateSuite certificateSuite){
		StoreHandling storeHandling = new StoreHandling();
		try {
			List<X509Certificate>  list = storeHandling.listStoredCertificates(certificateSuite);
			for(X509Certificate cert : list){
				displayX509Certificate(cert);
			}
		} catch (VeidblockException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}