package org.acreo.security.certificate;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.acreo.security.bc.CertificateHandlingBC;
import org.acreo.security.exceptions.VeidblockException;
import org.acreo.security.utils.DistinguishName;
import org.acreo.security.utils.PEMStream;
import org.acreo.security.utils.StoreHandling;
import org.bouncycastle.asn1.x500.X500Name;

public class CMSDelegator {

	private String keyStoreCredentials = null;
	private CertificateSuite certificateSuite;
	private CertificateHandlingBC certificateHandlingBC;

	public CMSDelegator(String keyStoreCredentials, CertificateSuite certificateSuite) {
		this.keyStoreCredentials = keyStoreCredentials;
		this.certificateSuite = certificateSuite;
		certificateHandlingBC = new CertificateHandlingBC(this.certificateSuite, this.keyStoreCredentials);
	}

	public boolean generateTopCACert(DistinguishName tca) throws VeidblockException {
		try {
			certificateHandlingBC.createSelfSignedCert(new X500Name(tca.toString()),
					this.certificateSuite.getCaLifeInYears(), this.certificateSuite.getAlgorithm());
			return true;
		} catch (Exception e) {
			throw new VeidblockException(e);
		}
	}

	public String fetchPkiPemChain(DistinguishName pkica) throws VeidblockException {
		StoreHandling storeHandling = new StoreHandling();
		X509Certificate x509CertificateChain[] = storeHandling.fetchCertificateChain(this.certificateSuite,
				this.keyStoreCredentials, pkica);
		PEMStream pemStream = new PEMStream();
		return pemStream.toPemCertChain(x509CertificateChain);
	}

	public X509Certificate fetchCACert(DistinguishName ca) throws VeidblockException {
		StoreHandling storeHandling = new StoreHandling();
		X509Certificate x509Certificate = storeHandling.fetchCertificate(this.certificateSuite,	ca);
		return x509Certificate;
	}

	public String fetchCApemChain(DistinguishName ca) throws VeidblockException {
		StoreHandling storeHandling = new StoreHandling();
		X509Certificate x509Certificate = storeHandling.fetchCertificate(this.certificateSuite,
				ca);
		if (x509Certificate == null) {
			try {
				throw new VeidblockException("Certificate of resource '" + ca.toString() + "' not exist !");
			} catch (Exception e) {
				throw new VeidblockException(e);
			}
		}
		X509Certificate x509CertificateChain[];
		try {
			x509CertificateChain = fetchChainByCert(x509Certificate, this.certificateSuite, this.keyStoreCredentials);
		} catch (Exception e) {
			throw new VeidblockException(e);
		}
		PEMStream pemStream = new PEMStream();
		return pemStream.toPemCertChain(x509CertificateChain);
	}

	public X509Certificate[] fetchCertChain(DistinguishName dn) throws VeidblockException {
		StoreHandling storeHandling = new StoreHandling();
		X509Certificate x509CertificateChain[] = storeHandling.fetchCertificateChain(this.certificateSuite,
				this.keyStoreCredentials, dn);
		return x509CertificateChain;
	}

	// ------------------------------------
	private X509Certificate[] fetchChainByCert(X509Certificate cAx509Certificate, CertificateSuite certificateSuite,
			String password) throws Exception {
		List<X509Certificate> chainList = new ArrayList<X509Certificate>();
		int i = 0;
		try {
			DistinguishName issuerDn = DistinguishName.builder().build(cAx509Certificate.getIssuerDN().toString());
			if (issuerDn == null) {
				throw new Exception("*Problems when creating issuer's distinguished name for fetching chain !");
			}
			DistinguishName dn = DistinguishName.builder().build(cAx509Certificate.getSubjectDN().toString());
			if (dn == null) {
				throw new Exception("*Problems when creating distinguished name for fetching chain !");
			}
			StoreHandling storeHandling = new StoreHandling();
			//storeHandling.displayList(certificateSuite, password);
			X509Certificate tempCert = storeHandling.fetchCertificate(certificateSuite, dn);
			if (null == tempCert) {
				throw new Exception("Certificate does not belong to our domain for fetching chain !");
			}
			while (true) {
				issuerDn = DistinguishName.builder().build(cAx509Certificate.getIssuerDN().toString());
				if (issuerDn == null) {
					throw new Exception("*Problems when creating issuer's distinguished name for fetching chain !");
				}
				dn = DistinguishName.builder().build(cAx509Certificate.getSubjectDN().toString());
				if (dn == null) {
					throw new Exception("*Problems when creating distinguished name for fetching chain !");
				}
				X509Certificate caCert = storeHandling.fetchCertificate(certificateSuite, issuerDn);
				if (caCert == null) {
					throw new Exception("Problems when fetching Isser's CA Certificate for fetching chain !");
				}
				if (dn.toString().equals(issuerDn.toString())) {
					chainList.add(i, cAx509Certificate);
					i++;
					X509Certificate x509Certificates[] = new X509Certificate[chainList.size()];
					for (int temp = 0; temp < chainList.size(); temp++) {
						x509Certificates[temp] = chainList.get(temp);
					}
					return x509Certificates;

				}
				chainList.add(i, cAx509Certificate);
				i++;
				cAx509Certificate = caCert;
			}
		} catch (Exception e) {
			throw new Exception("Problems when creating certificate chain !");
		}
	}

}
