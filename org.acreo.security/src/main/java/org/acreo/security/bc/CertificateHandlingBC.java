package org.acreo.security.bc;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.Random;

import org.acreo.security.certificate.CertificateSuite;
import org.acreo.security.exceptions.VeidblockException;
import org.acreo.security.utils.CertificateData;
import org.acreo.security.utils.CommonEnums.CERTIFICATE_VALIDITY_STATUS;
import org.acreo.security.utils.DistinguishName;
import org.acreo.security.utils.StoreHandling;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.bc.BcX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;

public class CertificateHandlingBC {

	private CertificateSuite certificateSuite;
	private String keyStoreCredentials;

	public CertificateHandlingBC(CertificateSuite certificateSuite, String keyStoreCredentials) {
		this.certificateSuite = certificateSuite;
		this.keyStoreCredentials = keyStoreCredentials;
	}

	
	public static int getClientKeyUsage() {
		return (KeyUsage.keyAgreement | KeyUsage.digitalSignature | KeyUsage.keyEncipherment);
	}
	public X509Certificate signCert(PrivateKey caKey, X509Certificate caCert, byte[] pkcs10) {
		try {

			PKCS10CertificationRequest pkcs10Req = new PKCS10CertificationRequest(pkcs10);
			if (!verifyCSR(pkcs10Req)) {
				return null;
			}

			Provider bcProvider = new BouncyCastleProvider();
			JcaPKCS10CertificationRequest jcaCertRequest = new JcaPKCS10CertificationRequest(pkcs10)
					.setProvider(bcProvider);
			PublicKey subjectPK = jcaCertRequest.getPublicKey();

			Date startDate = new Date();
			Calendar calendar = Calendar.getInstance();
			calendar.setTime(startDate);
			calendar.add(Calendar.YEAR, certificateSuite.getCertLifeInYears());
			Date expiryDate = calendar.getTime();

			BigInteger serial = BigInteger.valueOf(new Random().nextInt());
						
			X500Name issuer = new X500Name(caCert.getSubjectDN().toString());
			
			X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(issuer, serial, startDate, expiryDate,
					pkcs10Req.getSubject(), SubjectPublicKeyInfo.getInstance(subjectPK.getEncoded()));

			certBuilder.addExtension(Extension.subjectKeyIdentifier, false,
					createSubjectKeyIdentifier(subjectPK.getEncoded()));
			certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

			JcaContentSignerBuilder builder = new JcaContentSignerBuilder(certificateSuite.getSignatureAlgorithm());

			KeyUsage usage = new KeyUsage(KeyUsage.dataEncipherment | KeyUsage.digitalSignature
					| KeyUsage.keyEncipherment | KeyUsage.nonRepudiation);
			certBuilder.addExtension(Extension.keyUsage, false, usage);

			ASN1EncodableVector purposes = new ASN1EncodableVector();
			purposes.add(KeyPurposeId.id_kp_clientAuth);
			purposes.add(KeyPurposeId.anyExtendedKeyUsage);
			certBuilder.addExtension(Extension.extendedKeyUsage, false, new DERSequence(purposes));
			ContentSigner signer;

			signer = builder.build(caKey);

			byte[] certBytes = certBuilder.build(signer).getEncoded();
			CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
			X509Certificate certificate = (X509Certificate) certificateFactory
					.generateCertificate(new ByteArrayInputStream(certBytes));
			
			return certificate;
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * 
	 * @param issuerName
	 *            : Name of Root Certificate
	 * @param publicKey
	 *            : Public key the root certificate
	 * @param privateKey
	 *            : Private key the root certificate
	 * @return Return X509Certificate of the root entity
	 * @throws Exception
	 */
	public CertificateData createSelfSignedCert(X500Name issuerName, int life, String algorithm) throws Exception {
		Provider bcProvider = new BouncyCastleProvider();

		KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algorithm);
		keyGen.initialize(certificateSuite.getKeySize());
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

		String signatureAlgorithm = certificateSuite.getSignatureAlgorithm();//"SHA256WithRSA";

		ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).build(privateKey);
		X509Certificate cert = new JcaX509CertificateConverter().setProvider(bcProvider)
				.getCertificate(builder.build(contentSigner));
		
		
		cert.checkValidity(new Date());
		cert.verify(publicKey);

		CertificateData certificateData = new CertificateData(cert, privateKey);
		StoreHandling storeHandling = new StoreHandling();
		storeHandling.stroePrivateKeywithCertificate(certificateSuite, keyStoreCredentials,
				new X509Certificate[] { certificateData.getX509certificate() }, certificateData.getPrivateKey());
		return new CertificateData(certificateData.getX509certificate(), null);
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

	// --------------------------------------------------------
	public CertificateData createSelfSignedClientCert(DistinguishName distinguishName, int keyUsage) throws Exception {

		StoreHandling storeHandling = new StoreHandling();
		X509Certificate certificate = storeHandling.fetchCertificate(this.certificateSuite,
				distinguishName);
		//System.out.println("RSA Key Store : "+this.certificateSuite.getStorePath());
		if (certificate != null) {
			CERTIFICATE_VALIDITY_STATUS status = storeHandling.isValidCertificate(certificate);
			
			if (status == CERTIFICATE_VALIDITY_STATUS.VALID) {
				if (!certificate.getSubjectDN().toString().equals(certificate.getIssuerDN().toString())) {
					throw new VeidblockException("It is a valid certificate issued by an issuer !");
				} else {
					return new CertificateData(certificate, storeHandling.fetchPrivateKey(this.certificateSuite, this.keyStoreCredentials, distinguishName));
				}
			}else if (status == CERTIFICATE_VALIDITY_STATUS.NOT_VALID_YET) {
				if (!certificate.getSubjectDN().toString().equals(certificate.getIssuerDN().toString())) {
					throw new VeidblockException("Certificate already exisits but it is invalid !");
				}
			}
		}

		X500Name subject = new X500Name(distinguishName.toString());
		CertificateData certificateData = null;
		try {
			certificateData = createSelfSignedClientCert(subject, keyUsage);
		} catch (Exception e1) {
			throw new VeidblockException(e1);
		}
		// Store self cert into store

		X509Certificate chain[] = new X509Certificate[1];
		chain[0] = certificateData.getX509certificate();
		storeHandling.stroePrivateKeywithCertificate(this.certificateSuite, this.keyStoreCredentials, chain,
				certificateData.getPrivateKey());
		return certificateData;
		
	}
	public CertificateData createSelfSignedClientCertByForce(DistinguishName distinguishName, int keyUsage) throws Exception {

		StoreHandling storeHandling = new StoreHandling();
		X509Certificate certificate = storeHandling.fetchCertificate(this.certificateSuite,
				distinguishName);
		if (certificate != null) {
			CERTIFICATE_VALIDITY_STATUS status = storeHandling.isValidCertificate(certificate);
			
			if (status == CERTIFICATE_VALIDITY_STATUS.VALID) {
				if (!certificate.getSubjectDN().toString().equals(certificate.getIssuerDN().toString())) {
					throw new VeidblockException("It is a valid certificate issued by an issuer !");
				} 
			}else if (status == CERTIFICATE_VALIDITY_STATUS.NOT_VALID_YET) {
				if (!certificate.getSubjectDN().toString().equals(certificate.getIssuerDN().toString())) {
					throw new VeidblockException("Certificate already exisits but it is invalid !");
				}
			}
		}

		X500Name subject = new X500Name(distinguishName.toString());
		CertificateData certificateData = null;
		try {
			certificateData = createSelfSignedClientCert(subject, keyUsage);
		} catch (Exception e1) {
			throw new VeidblockException(e1);
		}
		// Store self cert into store

		X509Certificate chain[] = new X509Certificate[1];
		chain[0] = certificateData.getX509certificate();
		storeHandling.stroePrivateKeywithCertificate(this.certificateSuite, this.keyStoreCredentials, chain,
				certificateData.getPrivateKey());
		return certificateData;
		
	}
	
	
	public CertificateData createSelfSignedClientCert(X500Name issuerName, int keyUsage) throws Exception {
		Provider bcProvider = new BouncyCastleProvider();

		KeyPairGenerator keyGen = KeyPairGenerator.getInstance(certificateSuite.getAlgorithm());
		keyGen.initialize(certificateSuite.getKeySize());
		KeyPair pair = keyGen.generateKeyPair();
		PrivateKey privateKey = pair.getPrivate();
		PublicKey publicKey = pair.getPublic();

		Date startDate = new Date();

		BigInteger certSerialNumber = new BigInteger(Long.toString(System.currentTimeMillis()));

		Calendar calendar = Calendar.getInstance();
		calendar.setTime(startDate);
		calendar.add(Calendar.YEAR, 1);
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

		KeyUsage usage = new KeyUsage(keyUsage);
		builder.addExtension(Extension.keyUsage, false, usage);

		ASN1EncodableVector purposes = new ASN1EncodableVector();
		purposes.add(KeyPurposeId.id_kp_serverAuth);
		purposes.add(KeyPurposeId.anyExtendedKeyUsage);
		builder.addExtension(Extension.extendedKeyUsage, false, new DERSequence(purposes));

		String signatureAlgorithm = certificateSuite.getSignatureAlgorithm();//"SHA256WithRSA";

		ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).build(privateKey);
		X509Certificate cert = new JcaX509CertificateConverter().setProvider(bcProvider)
				.getCertificate(builder.build(contentSigner));
		
		
		cert.checkValidity(new Date());
		cert.verify(publicKey);

		CertificateData certificateData = new CertificateData(cert, privateKey);
		StoreHandling storeHandling = new StoreHandling();
		storeHandling.stroePrivateKeywithCertificate(certificateSuite, keyStoreCredentials,
				new X509Certificate[] { certificateData.getX509certificate() }, certificateData.getPrivateKey());
		
		storeHandling.storeCertificate(certificateSuite, certificateData.getX509certificate());
		
		return certificateData;
	}

	// --------------------------------------------------------
	public byte[] createCSR(DistinguishName distinguishName, int keyUsage) throws VeidblockException {

		StoreHandling storeHandling = new StoreHandling();
		X509Certificate certificate = storeHandling.fetchCertificate(this.certificateSuite,
				distinguishName);
		if (certificate != null) {
			CERTIFICATE_VALIDITY_STATUS status = storeHandling.isValidCertificate(certificate);
			if (status == CERTIFICATE_VALIDITY_STATUS.VALID) {
				if (!certificate.getSubjectDN().toString().equals(certificate.getIssuerDN().toString())) {
					throw new VeidblockException("Certificate already exisits and its valid !");
				}
			}else if (status == CERTIFICATE_VALIDITY_STATUS.NOT_VALID_YET) {
				if (!certificate.getSubjectDN().toString().equals(certificate.getIssuerDN().toString())) {
					throw new VeidblockException("Certificate already exisits and its not valid yet !");
				}
			}
		}

		X500Name subject = new X500Name(distinguishName.toString());
		CertificateData certificateData = null;
		try {
			certificateData = createSelfSignedClientCert(subject, keyUsage);
		} catch (Exception e1) {
			throw new VeidblockException(e1);
		}
		// Store self cert into store

		X509Certificate chain[] = new X509Certificate[1];
		chain[0] = certificateData.getX509certificate();
		storeHandling.stroePrivateKeywithCertificate(this.certificateSuite, this.keyStoreCredentials, chain,
				certificateData.getPrivateKey());
		try {

			AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(certificateSuite.getSignatureAlgorithm());//"SHA256WithRSA");
			AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);

			AsymmetricKeyParameter privateKeyAsymKeyParam = PrivateKeyFactory
					.createKey(certificateData.getPrivateKey().getEncoded());

			ContentSigner sigGen = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(privateKeyAsymKeyParam);

			SubjectPublicKeyInfo subPubKeyInfo = SubjectPublicKeyInfo
					.getInstance(certificateData.getPublicKey().getEncoded());
			PKCS10CertificationRequestBuilder builder = new PKCS10CertificationRequestBuilder(subject, subPubKeyInfo);

			ExtensionsGenerator extGen = new ExtensionsGenerator();

			extGen.addExtension(Extension.keyUsage, true, new KeyUsage(keyUsage));

			builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate());
			PKCS10CertificationRequest csr = builder.build(sigGen);
		
			if (verifyCSR(csr)) {

				return csr.getEncoded();
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	public boolean verifyCSR(final PKCS10CertificationRequest p10Request) throws Exception {
		Provider bcProvider = new BouncyCastleProvider();
		String sigName = certificateSuite.getSignatureAlgorithm();// "SHA256WithRSA";
		if (p10Request.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider(bcProvider)
				.build(p10Request.getSubjectPublicKeyInfo()))) {
			return true;
		} else {
			
			return false;
		}
	}
	public String getRSACertificateStorePath() {
		return this.certificateSuite.getStorePath();
	}
}