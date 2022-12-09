package org.acreo.security.utils;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

public class CertificateData {
	
	private X509Certificate x509certificate = null;
	private PrivateKey privateKey = null;
	private PublicKey publicKey = null;
	public CertificateData (X509Certificate x509certificate , PrivateKey privateKey){
		this.x509certificate = x509certificate;
		this.privateKey = privateKey;
	}
	
	public X509Certificate getX509certificate() {
		return x509certificate;
	}

	public void setX509certificate(X509Certificate x509certificate) {
		this.x509certificate = x509certificate;
	}

	public PrivateKey getPrivateKey() {
		return privateKey;
	}
	public void setPrivateKey(PrivateKey privateKey) {
		this.privateKey = privateKey;
	}
	public PublicKey getPublicKey() {
		if (null != x509certificate){
			return x509certificate.getPublicKey();
		}
		return null;
	}	
}
