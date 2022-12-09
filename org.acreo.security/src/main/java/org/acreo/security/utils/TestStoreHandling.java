package org.acreo.security.utils;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.Random;

import org.acreo.security.certificate.CertificateSuite;
import org.acreo.security.debug.DisplayCertProps;
import org.acreo.security.exceptions.VeidblockException;
import org.acreo.security.utils.CommonEnums.CERTIFICATE_VALIDITY_STATUS;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.bc.BcX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class TestStoreHandling {

	
	//----------------------Private Store Handling------------------------------------
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

	//----------------------------------------------------------
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

	public boolean storeCertificate(CertificateSuite certificateSuite, X509Certificate cert)
			throws VeidblockException {
		try {
			if (!createStore(certificateSuite)) {
				return false;
			}
			long keyusage = 0;
			X509Certificate stroedCert = chkCertificateExists(certificateSuite,
					DistinguishName.builder().build(cert.getSubjectDN().toString()), keyusage);
			// Store this certificate in revoke/deleted list
			if (null != stroedCert) {
				deleteCertificate(certificateSuite,	DistinguishName.builder().build(cert.getSubjectDN().toString()));
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

	public X509Certificate fetchCertificate(CertificateSuite certificateSuite,
			DistinguishName distinguishName) throws VeidblockException {
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

	public X509Certificate fetchCertificate(CertificateSuite certificateSuite,
			DistinguishName distinguishName, long keyusage) throws VeidblockException {
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

	public boolean deleteCertificate(CertificateSuite certificateSuite,
			DistinguishName distinguishName) throws VeidblockException {
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

	public void displayList(CertificateSuite certificateSuite, String password) {
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

	public X509Certificate chkCertificateExists(CertificateSuite certificateSuite,
			DistinguishName distinguishName, long keyusage) {
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

	private static SubjectKeyIdentifier createSubjectKeyIdentifier(byte[] encodedKey) throws IOException {
		ASN1InputStream is = null;
		try {
			is = new ASN1InputStream(new ByteArrayInputStream(encodedKey));
			ASN1Sequence seq = (ASN1Sequence) is.readObject();
			SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(seq);
			return new BcX509ExtensionUtils().createSubjectKeyIdentifier(info);
		} finally {
			is.close();
		}
	}

	public CertificateData createSelfSignedCert(CertificateSuite certificateSuite, String keyStoreCredentials,
			X500Name issuerName, int life, String algorithm) throws Exception {
		Provider bcProvider = new BouncyCastleProvider();

		KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algorithm);
		keyGen.initialize(2048);
		KeyPair pair = keyGen.generateKeyPair();
		PrivateKey privateKey = pair.getPrivate();
		PublicKey publicKey = pair.getPublic();

		Date startDate = new Date();

		BigInteger certSerialNumber = new BigInteger(Long.toString(System.currentTimeMillis()));

		Calendar calendar = Calendar.getInstance();
		calendar.setTime(startDate);
		calendar.add(Calendar.YEAR, life);
		Date endDate = calendar.getTime();

		//
		// serial
		//
		BigInteger serial = BigInteger.valueOf(new Random().nextInt());

		//
		// create the certificate - version 3
		//
		X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuerName, serial, startDate, endDate,
				issuerName, publicKey);
		builder.addExtension(Extension.subjectKeyIdentifier, false, createSubjectKeyIdentifier(publicKey.getEncoded()));
		builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));

		KeyUsage usage = new KeyUsage(
				KeyUsage.keyCertSign | KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.cRLSign);
		builder.addExtension(Extension.keyUsage, false, usage);

		ASN1EncodableVector purposes = new ASN1EncodableVector();
		purposes.add(KeyPurposeId.id_kp_serverAuth);
		purposes.add(KeyPurposeId.anyExtendedKeyUsage);
		builder.addExtension(Extension.extendedKeyUsage, false, new DERSequence(purposes));

		String signatureAlgorithm = "SHA256WithRSA";

		ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).build(privateKey);
		X509Certificate cert = new JcaX509CertificateConverter().setProvider(bcProvider)
				.getCertificate(builder.build(contentSigner));
		System.out.println("===========================================");
		System.out.println(cert.toString());
		cert.checkValidity(new Date());
		cert.verify(publicKey);

		CertificateData certificateData = new CertificateData(cert, privateKey);
		System.out.println(privateKey.toString());
		stroePrivateKeywithCertificate(certificateSuite, keyStoreCredentials,
				new X509Certificate[] { certificateData.getX509certificate() }, certificateData.getPrivateKey());
		return new CertificateData(certificateData.getX509certificate(), null);
	}

	public static void main(String arg[]) throws Exception {
		TestStoreHandling testStoreHandling = new TestStoreHandling();

		CertificateSuite certificateSuite = new CertificateSuite("temp", 2);
		DistinguishName tca = DistinguishName.builder().name("tca").build();

		CertificateData certificate = testStoreHandling.createSelfSignedCert(certificateSuite, "123456789",
				new X500Name(tca.toString()), 3, certificateSuite.getAlgorithm());

		List<X509Certificate> list = testStoreHandling.listStoredCertificates(certificateSuite);
		DisplayCertProps certProps = new DisplayCertProps();
		for (X509Certificate x509certificate : list) {
			certProps.displayX509Certificate(x509certificate);
		}
		System.out.println(testStoreHandling.fetchPrivateKey(certificateSuite, "123456789", tca).toString());

	}

}
