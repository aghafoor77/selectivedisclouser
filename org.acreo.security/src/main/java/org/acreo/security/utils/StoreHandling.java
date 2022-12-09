package org.acreo.security.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import org.acreo.security.certificate.CertificateSuite;
import org.acreo.security.exceptions.VeidblockException;
import org.acreo.security.utils.CommonEnums.CERTIFICATE_VALIDITY_STATUS;

public class StoreHandling {

	
	// ----------------------Private Store
	// Handling------------------------------------
	public boolean createPrivateKeyStore(CertificateSuite certificateSuite, String password) throws VeidblockException {
		File temp = new File(certificateSuite.getStorePath());
	
		if (temp.exists()) {
			return true;
		}
		KeyStore keyStore;
		try {
			keyStore = KeyStore.getInstance(certificateSuite.getStoreType());
			keyStore.load(null, null);
			keyStore.store(new FileOutputStream(certificateSuite.getPrivateKeyStorePath()), password.toCharArray());
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
			System.err.println("Problems when creting private key store at store path: "+certificateSuite.getStorePath());
			throw new VeidblockException(e);
		}
		return true;

	}

	public boolean stroePrivateKeywithCertificate(CertificateSuite certificateSuite, String password,
			X509Certificate[] chain, Key key) throws VeidblockException {
		try {
			createPrivateKeyStore(certificateSuite, password);
			KeyStore keyStore = this.openPrivateKeyStore(certificateSuite, password);
			keyStore.setKeyEntry(DistinguishName.builder().build(chain[0].getSubjectDN().toString()).getId(), key,
					password.toCharArray(), chain);
			keyStore.store(new FileOutputStream(certificateSuite.getPrivateKeyStorePath()), password.toCharArray());

			for (X509Certificate certificate : chain) {
				storeCertificate(certificateSuite, certificate);
			}

		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
			throw new VeidblockException(e);
		}
		return true;

	}

	public PrivateKey fetchPrivateKey(CertificateSuite certificateSuite, String password,
			DistinguishName distinguishName) throws VeidblockException {
		PrivateKey privateKey = null;
		if (null == distinguishName.getId()) {
			throw new NullPointerException("Common name is null !");
		}
		try {
			KeyStore keyStore = this.openPrivateKeyStore(certificateSuite, password);
			privateKey = (PrivateKey) keyStore.getKey(distinguishName.getId(), password.toCharArray());
		} catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException e) {
			throw new VeidblockException(e);
		}
		return privateKey;
	}

	public X509Certificate[] fetchCertificateChain(CertificateSuite certificateSuite, String password,
			DistinguishName distinguishName) throws VeidblockException {
		if (null == distinguishName.getId()) {
			throw new VeidblockException(new NullPointerException("Common name is null !"));
		}
		try {
			KeyStore keyStore = this.openPrivateKeyStore(certificateSuite, password);
			Certificate[] chain = null;
			chain = keyStore.getCertificateChain(distinguishName.getId());
			if (chain == null) {
				throw new VeidblockException(
						new NullPointerException("Problems when fetching chain of " + distinguishName.toString()));
			}
			X509Certificate x509Certificate[] = new X509Certificate[chain.length];
			for (int i = 0; i < chain.length; i++) {
				x509Certificate[i] = (X509Certificate) chain[i];
			}
			return x509Certificate;
		} catch (KeyStoreException e) {
			throw new VeidblockException(e);
		}
	}

	public boolean deleteCertificateStoredWithPrivateKey(CertificateSuite certificateSuite, String password,
			DistinguishName distinguishName) throws VeidblockException {
		KeyStore keyStore = this.openKeyStore(certificateSuite);
		try {
			keyStore.deleteEntry(distinguishName.getId());
			keyStore.store(new FileOutputStream(certificateSuite.getPrivateKeyStorePath()), password.toCharArray());
			return true;
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
			throw new VeidblockException(e);
		}
	}

	// ----------------------------------------------------------
	public boolean createStore(CertificateSuite certificateSuite) throws VeidblockException {
		File temp = new File(certificateSuite.getStorePath());
		if (temp.exists()) {
			return true;
		}
		KeyStore keyStore;
		try {
			keyStore = KeyStore.getInstance(certificateSuite.getStoreType());
			keyStore.load(null, null);
			keyStore.store(new FileOutputStream(certificateSuite.getStorePath()), "".toCharArray());
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
			throw new VeidblockException(e);
		}
		return true;

	}

	public boolean storeCertificate(CertificateSuite certificateSuite, X509Certificate cert) throws VeidblockException {
		try {
			if (!createStore(certificateSuite)) {
				return false;
			}
			long keyusage = 0;
			X509Certificate stroedCert = chkCertificateExists(certificateSuite,
					DistinguishName.builder().build(cert.getSubjectDN().toString()), keyusage);
			// Store this certificate in revoke/deleted list
			if (null != stroedCert) {
				deleteCertificate(certificateSuite, DistinguishName.builder().build(cert.getSubjectDN().toString()));
			}
			KeyStore keyStore = this.openKeyStore(certificateSuite);
			keyStore.setCertificateEntry(DistinguishName.builder().build(cert.getSubjectDN().toString()).getId(), cert);
			// keyStore.setCertificateEntry(DistinguishName.builder().build(cert.getSubjectDN().toString()).getId(),
			// cert);
			keyStore.store(new FileOutputStream(certificateSuite.getStorePath()), "".toCharArray());
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
			e.printStackTrace();
			throw new VeidblockException(e);
		}
		return true;
	}

	public X509Certificate fetchCertificate(CertificateSuite certificateSuite, DistinguishName distinguishName)
			throws VeidblockException {
		if (null == distinguishName.getId()) {
			throw new VeidblockException(new NullPointerException("Common name is null !"));
		}
		try {
			KeyStore keyStore = this.openKeyStore(certificateSuite);
			X509Certificate cert = null;
			cert = (X509Certificate) keyStore.getCertificate(distinguishName.getId());
			return cert;
		} catch (KeyStoreException e) {
			throw new VeidblockException(e);
		}
	}

	public List<X509Certificate> fetchCertificateByDn(CertificateSuite certificateSuite,
			DistinguishName distinguishName) throws VeidblockException {
		try {
			KeyStore keyStore = this.openKeyStore(certificateSuite);
			Enumeration<String> aliases = keyStore.aliases();
			List<X509Certificate> certificates = new ArrayList<>();
			while (aliases.hasMoreElements()) {
				X509Certificate cert = (X509Certificate) keyStore.getCertificate(aliases.nextElement());
				if (cert.getSubjectDN().toString().equals(distinguishName.toString())) {
					certificates.add(cert);
				}
			}
			return certificates;
		} catch (KeyStoreException e) {
			throw new VeidblockException(e);
		}
	}

	public X509Certificate fetchCertificate(CertificateSuite certificateSuite, DistinguishName distinguishName,
			long keyusage) throws VeidblockException {
		try {
			KeyStore keyStore = this.openKeyStore(certificateSuite);
			Enumeration<String> aliases = keyStore.aliases();
			while (aliases.hasMoreElements()) {
				X509Certificate cert = (X509Certificate) keyStore.getCertificate(aliases.nextElement());
				if (isMatchCriteria(cert, distinguishName, keyusage)) {
					return cert;
				}
			}
			throw new VeidblockException("Certificate not found !");
		} catch (KeyStoreException e) {
			throw new VeidblockException(e);
		}
	}

	private boolean isMatchCriteria(X509Certificate cert, DistinguishName distinguishName, long keyusage) {
		if (!cert.getSubjectDN().toString().equals(distinguishName.toString())) {
			return false;
		}
		/*
		 * if (new PKIUtil().getKeyUsage(cert.getKeyUsage()) != keyusage) {
		 * return false; }
		 */
		return true;
	}

	public List<X509Certificate> listStoredCertificates(CertificateSuite certificateSuite) throws VeidblockException {
		try {
			KeyStore keyStore = this.openKeyStore(certificateSuite);
			Enumeration<String> aliases = keyStore.aliases();
			List<X509Certificate> certificates = new ArrayList<X509Certificate>();
			while (aliases.hasMoreElements()) {
				X509Certificate cert;
				cert = (X509Certificate) keyStore.getCertificate(aliases.nextElement());
				certificates.add(cert);
			}
			return certificates;
		} catch (KeyStoreException e) {
			throw new VeidblockException(e);
		}
	}

	public boolean deleteCertificate(CertificateSuite certificateSuite, DistinguishName distinguishName)
			throws VeidblockException {
		KeyStore keyStore = this.openKeyStore(certificateSuite);
		try {
			keyStore.deleteEntry(distinguishName.getId());
			keyStore.store(new FileOutputStream(certificateSuite.getStorePath()), "".toCharArray());
			return true;
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
			throw new VeidblockException(e);
		}
	}

	private KeyStore openKeyStore(CertificateSuite certificateSuite) throws VeidblockException {
		KeyStore keyStore = null;
		try {
			keyStore = KeyStore.getInstance(certificateSuite.getStoreType());
			try {
				keyStore.load(new FileInputStream(certificateSuite.getStorePath()), "".toCharArray());
			} catch (Exception exp) {
				keyStore.load(null, null);
			}
			return keyStore;
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
			throw new VeidblockException(e);
		}
	}

	private KeyStore openPrivateKeyStore(CertificateSuite certificateSuite, String password) throws VeidblockException {
		KeyStore keyStore = null;
		try {
			keyStore = KeyStore.getInstance(certificateSuite.getStoreType());
			try {
				keyStore.load(new FileInputStream(certificateSuite.getPrivateKeyStorePath()), password.toCharArray());
			} catch (Exception exp) {
				keyStore.load(null, null);
			}
			return keyStore;
		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
			throw new VeidblockException(e);
		}
	}

	/*public void displayList(CertificateSuite certificateSuite, String password) {
		try {
			KeyStore keyStore = this.openKeyStore(certificateSuite);
			Enumeration<String> aliases = keyStore.aliases();
			List<X509Certificate> certificates = new ArrayList<X509Certificate>();
			int count = 1;
			while (aliases.hasMoreElements()) {
				X509Certificate cert;
				cert = (X509Certificate) keyStore.getCertificate(aliases.nextElement());
				DisplayCertProps certProps = new DisplayCertProps();
				System.out.println("-----------COUNT=" + count + "------------");
				certProps.displayX509Certificate(cert);
				count++;
				certificates.add(cert);
			}
		} catch (VeidblockException | KeyStoreException e) {
			e.printStackTrace();
		}
	}
*/
	public X509Certificate chkCertificateExists(CertificateSuite certificateSuite, DistinguishName distinguishName,
			long keyusage) {
		X509Certificate certificate = null;
		try {
			certificate = fetchCertificate(certificateSuite, distinguishName, keyusage);
			if (certificate != null) {
				return certificate;
			}
		} catch (VeidblockException e) {
		}
		return certificate;
	}

	public CERTIFICATE_VALIDITY_STATUS isValidCertificate(X509Certificate certificate) {
		try {
			certificate.checkValidity();
		} catch (CertificateExpiredException e) {
			return CERTIFICATE_VALIDITY_STATUS.EXPIRED;
		} catch (CertificateNotYetValidException e) {
			return CERTIFICATE_VALIDITY_STATUS.NOT_VALID_YET;
		}
		return CERTIFICATE_VALIDITY_STATUS.VALID;
	}
}
