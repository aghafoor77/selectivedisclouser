package org.acreo.security.pkcs;

import java.io.ByteArrayOutputStream;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import org.acreo.security.certificate.CertificateSuite;
import org.acreo.security.exceptions.VeidblockException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

public class PKCS7SignedData {

	private CertificateSuite certificateSuite;

	public PKCS7SignedData(CertificateSuite certificateSuite) {
		this.certificateSuite = certificateSuite;
	}

	public byte[] generatePKCS7Signed(X509Certificate[] senderChain, PrivateKey senderPrivateKey, byte[] dataToSign)
			throws VeidblockException {
		try {

			Provider bcProvider = new BouncyCastleProvider();
			List<X509Certificate> certList = new ArrayList<X509Certificate>();
			CMSTypedData msg = new CMSProcessableByteArray(dataToSign);
			for (X509Certificate certSigner : senderChain) {
				certList.add(certSigner);
			}

			Store certs = new JcaCertStore(certList);
			CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
			ContentSigner senderSigner;

			senderSigner = new JcaContentSignerBuilder(this.certificateSuite.getSignatureAlgorithm())
					.setProvider(bcProvider).build(senderPrivateKey);

			gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
					new JcaDigestCalculatorProviderBuilder().setProvider(bcProvider).build()).build(senderSigner,
							senderChain[0]));
			gen.addCertificates(certs);
			CMSSignedData sigData = gen.generate(msg, true);
			return sigData.getEncoded();
		} catch (Exception e) {
			throw new VeidblockException(e);
		}
	}

	public byte[] generatePKCS7Signed(X509Certificate[] senderChain, PrivateKey senderPrivateKey,
			X509Certificate[] ipvChain, PrivateKey ipvPrivateKey, byte[] dataToSign) throws VeidblockException {
		try {

			Provider bcProvider = new BouncyCastleProvider();

			// Build CMS

			List<X509Certificate> certList = new ArrayList<X509Certificate>();
			CMSTypedData msg = new CMSProcessableByteArray(dataToSign);
			for (X509Certificate certSigner : senderChain) {
				certList.add(certSigner);
			}
			for (X509Certificate certSigner : ipvChain) {
				certList.add(certSigner);
			}

			Store certs = new JcaCertStore(certList);
			CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

			ContentSigner senderSigner = new JcaContentSignerBuilder(this.certificateSuite.getSignatureAlgorithm())
					.setProvider(bcProvider).build(senderPrivateKey);
			ContentSigner ipvSigner = new JcaContentSignerBuilder(this.certificateSuite.getSignatureAlgorithm())
					.setProvider(bcProvider).build(ipvPrivateKey);

			SignerInfoGenerator generator = null;
			
			gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
					new JcaDigestCalculatorProviderBuilder().setProvider(bcProvider).build()).build(senderSigner,
							senderChain[0]));

			gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
					new JcaDigestCalculatorProviderBuilder().setProvider(bcProvider).build()).build(ipvSigner,
							ipvChain[0]));

			gen.addCertificates(certs);
			CMSSignedData sigData = gen.generate(msg, true);
			return sigData.getEncoded();
		} catch (Exception e) {
			throw new VeidblockException(e);
		}
	}

	// ,
	public byte[] generatePKCS7Signed(List<VeidSignerInfo> veidSignerInfoList, byte[] dataToSign)
			throws VeidblockException {
		try {

			Provider bcProvider = new BouncyCastleProvider();

			// Build CMS

			List<X509Certificate> certList = new ArrayList<X509Certificate>();
			CMSTypedData msg = new CMSProcessableByteArray(dataToSign);
			
			CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
			
			for (VeidSignerInfo veidSignerInfo : veidSignerInfoList) {
				for (X509Certificate certSigner : veidSignerInfo.getChain() ) {
					certList.add(certSigner);
				}
				
				ContentSigner senderSigner = new JcaContentSignerBuilder(this.certificateSuite.getSignatureAlgorithm())
						.setProvider(bcProvider).build(veidSignerInfo.getPrivateKey());
				gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
						new JcaDigestCalculatorProviderBuilder().setProvider(bcProvider).build()).build(senderSigner,
								veidSignerInfo.getChain()[0]));
				
			}

			Store certs = new JcaCertStore(certList);
			gen.addCertificates(certs);
			CMSSignedData sigData = gen.generate(msg, true);
			return sigData.getEncoded();
		} catch (Exception e) {
			throw new VeidblockException(e);
		}
	}

	/*public byte[] addCounterSignature(List<VeidSignerInfo> veidSignerInfoList, CMSSignedData sigData)
			throws VeidblockException {
		try {

			Provider bcProvider = new BouncyCastleProvider();

			// Build CMS

			List<X509Certificate> certList = new ArrayList<X509Certificate>();
			CMSTypedData msg = new CMSProcessableByteArray(dataToSign);
			
			CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
			
			for (VeidSignerInfo veidSignerInfo : veidSignerInfoList) {
				for (X509Certificate certSigner : veidSignerInfo.getChain() ) {
					certList.add(certSigner);
				}
				
				ContentSigner senderSigner = new JcaContentSignerBuilder(this.certificateSuite.getSignatureAlgorithm())
						.setProvider(bcProvider).build(veidSignerInfo.getPrivateKey());
				gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
						new JcaDigestCalculatorProviderBuilder().setProvider(bcProvider).build()).build(senderSigner,
								veidSignerInfo.getChain()[0]));
				
			}

			Store certs = new JcaCertStore(certList);
			gen.addCertificates(certs);
			CMSSignedData sigData = gen.generate(msg, true);
			return sigData.getEncoded();
		} catch (Exception e) {
			throw new VeidblockException(e);
		}
	}*/
	
	public byte[] openPKCS7SignedEData(byte[] signedDataEncoded) throws VeidblockException {
		try {
			Provider bcProvider = new BouncyCastleProvider();
			CMSSignedData signedData = new CMSSignedData(signedDataEncoded);
			
			Store store = signedData.getCertificates();
			SignerInformationStore signers = signedData.getSignerInfos();
			Collection c = signers.getSigners();
			int totalSigner = c.size();
			Iterator it = c.iterator();

			while (it.hasNext()) {

				SignerInformation signer = (SignerInformation) it.next();
				Collection certCollection = store.getMatches(signer.getSID());
				Iterator certIt = certCollection.iterator();
				X509CertificateHolder certHolder = (X509CertificateHolder) certIt.next();
				X509Certificate certTemp = new JcaX509CertificateConverter().setProvider(bcProvider)
						.getCertificate(certHolder);

				if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(bcProvider).build(certTemp))) {					

				} else {
					throw new VeidblockException("Problems when verifying PKCS7 Signed data !");
				}
			}
			ByteArrayOutputStream out = null;
			out = new ByteArrayOutputStream();
			signedData.getSignedContent().write(out);
			
			byte[] byte_out = out.toByteArray();
			return byte_out;
		} catch (Exception e) {
			throw new VeidblockException(e);
		}
	}

	public X509Certificate[] getSignerCertificates(byte[] signedDataEncoded) throws VeidblockException {
		X509Certificate signersCert[] = null;
		try {
			Provider bcProvider = new BouncyCastleProvider();
			CMSSignedData signedData = new CMSSignedData(signedDataEncoded);
			Store store = signedData.getCertificates();
			SignerInformationStore signers = signedData.getSignerInfos();
			Collection c = signers.getSigners();

			signersCert = new X509Certificate[c.size()];
			Iterator it = c.iterator();

			int i = 0;
			while (it.hasNext()) {

				SignerInformation signer = (SignerInformation) it.next();
				Collection certCollection = store.getMatches(signer.getSID());
				Iterator certIt = certCollection.iterator();
				X509CertificateHolder certHolder = (X509CertificateHolder) certIt.next();
				X509Certificate certTemp = new JcaX509CertificateConverter().setProvider(bcProvider)
						.getCertificate(certHolder);
				signersCert[i] = certTemp;
				i++;

			}
			return signersCert;
		} catch (Exception e) {
			throw new VeidblockException(e);
		}
	}

	public X509Certificate[] getx509CertFromPKCS7SignedData(byte[] signedDataEncoded) throws VeidblockException {
		try {
			Provider bcProvider = new BouncyCastleProvider();
			CMSSignedData signedData = new CMSSignedData(signedDataEncoded);
			Store<X509CertificateHolder> store = signedData.getCertificates();
			ArrayList<X509CertificateHolder> listCertDatFirm = new ArrayList(store.getMatches(null));
			X509Certificate[] extractedList = new X509Certificate[listCertDatFirm.size()];
			int i = 0;
			for (X509CertificateHolder x509CertificateHolder : listCertDatFirm) {
				X509Certificate certTemp = new JcaX509CertificateConverter().setProvider(bcProvider)
						.getCertificate(x509CertificateHolder);
				extractedList[i] = certTemp;
				i++;
			}
			return extractedList;
		} catch (Exception e) {
			throw new VeidblockException(e);
		}
	}
}