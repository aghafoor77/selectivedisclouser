package org.acreo.security.pkcs;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;

import org.acreo.security.certificate.CertificateSuite;
import org.acreo.security.crypto.CryptoPolicy;
import org.acreo.security.exceptions.VeidblockException;

public class PKCS7Manager {
	private CryptoPolicy cryptoPolicy;

	private CertificateSuite certificateSuite;
	public PKCS7Manager(CryptoPolicy cryptoPolicy, CertificateSuite certificateSuite) {
		this.cryptoPolicy = cryptoPolicy;
		this.certificateSuite = certificateSuite;
	}

	public String generateEnvelopedData(X509Certificate[] recipients, byte[] dataToEnvelop) throws VeidblockException {
		PKCS7EnvelopedData pkcs7EnvelopedData = new PKCS7EnvelopedData(cryptoPolicy);
		byte base64Enveloped []= Base64.getEncoder().encode(pkcs7EnvelopedData.generateEnvelopedData(recipients, dataToEnvelop));
		return new String(base64Enveloped);
	}

	public byte[] openEnvelopedData(X509Certificate certificate, PrivateKey privateKey, String envelopedData)
			throws VeidblockException {
		PKCS7EnvelopedData pkcs7EnvelopedData = new PKCS7EnvelopedData(cryptoPolicy);
		byte decodedEnveloped []= Base64.getDecoder().decode(envelopedData);
		return pkcs7EnvelopedData.openEnvelopedData(certificate, privateKey, decodedEnveloped );
	}

	public String generatePKCS7SignedAndEnveloped(X509Certificate[] signerChain, PrivateKey signerPrivateKey, X509Certificate[] recipients, byte[] data)
			throws VeidblockException {
		
		PKCS7EnvelopedData pkcs7EnvelopedData = new PKCS7EnvelopedData(cryptoPolicy);
		byte[] envelopedData = pkcs7EnvelopedData.generateEnvelopedData(recipients, data);
		
		PKCS7SignedData pkcs7SignedData = new PKCS7SignedData(this.certificateSuite);
		
		byte base64Enveloped []= Base64.getEncoder().encode(pkcs7SignedData.generatePKCS7Signed(signerChain, signerPrivateKey, envelopedData));
		return new String(base64Enveloped);
	}	
	
	public byte[] openPKCS7SignedAndEnveloped(X509Certificate certificate, PrivateKey privateKey,String pkcs7Data)
			throws VeidblockException {
		
		byte pkcs7DataBytea [] = Base64.getDecoder().decode(pkcs7Data);
		
		PKCS7SignedData pkcs7SignedData = new PKCS7SignedData(this.certificateSuite);
		
		byte [] verifiedData = pkcs7SignedData.openPKCS7SignedEData(pkcs7DataBytea );
		
		PKCS7EnvelopedData pkcs7EnvelopedData = new PKCS7EnvelopedData(cryptoPolicy);
		return pkcs7EnvelopedData.openEnvelopedData(certificate, privateKey, verifiedData);		
	}	
	
	public String generatePKCS7Signed(List<VeidSignerInfo> veidSignerInfoList, byte[] dataToSign)
			throws VeidblockException {
		
		PKCS7SignedData pkcs7SignedData = new PKCS7SignedData(this.certificateSuite);
		//X509Certificate[] serverChain, PrivateKey serverPrivateKey,
		
		byte [] signed = pkcs7SignedData.generatePKCS7Signed(veidSignerInfoList, dataToSign);
		return Base64.getEncoder().encodeToString(signed);		
		
	}

	public byte[] openPKCS7SignedData(String pkcs7Data) throws VeidblockException {
		PKCS7SignedData pkcs7SignedData = new PKCS7SignedData(this.certificateSuite);
		byte[] signedDataDecoded = Base64.getDecoder().decode(pkcs7Data);
		return pkcs7SignedData.openPKCS7SignedEData(signedDataDecoded);
	}

	public X509Certificate[] getx509CertPKCS7SignedData(String pkcs7Data) throws VeidblockException {
		PKCS7SignedData pkcs7SignedData = new PKCS7SignedData(this.certificateSuite);
		byte[] signedDataDecoded = Base64.getDecoder().decode(pkcs7Data);
		return pkcs7SignedData.getx509CertFromPKCS7SignedData(signedDataDecoded);
	}

}