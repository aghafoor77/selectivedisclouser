package org.acreo.security.pkcs;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class VeidSignerInfo {
	
	private X509Certificate[] chain;
	private PrivateKey privateKey;
	public X509Certificate[] getChain() {
		return chain;
	}
	public void setChain(X509Certificate[] chain) {
		this.chain = chain;
	}
	public PrivateKey getPrivateKey() {
		return privateKey;
	}
	public void setPrivateKey(PrivateKey privateKey) {
		this.privateKey = privateKey;
	}
}
