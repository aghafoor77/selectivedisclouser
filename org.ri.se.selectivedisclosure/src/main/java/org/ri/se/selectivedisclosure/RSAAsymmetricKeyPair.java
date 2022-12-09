package org.ri.se.selectivedisclosure;

import java.security.PrivateKey;
import java.security.PublicKey;

public class RSAAsymmetricKeyPair {
	
	private PublicKey publicKey;
	private PrivateKey privateKey;
	
	public RSAAsymmetricKeyPair(PublicKey publicKey, PrivateKey privateKey) {
		super();
		this.publicKey = publicKey;
		this.privateKey = privateKey;
	}
	public PublicKey getPublicKey() {
		return publicKey;
	}
	public void setPublicKey(PublicKey publicKey) {
		this.publicKey = publicKey;
	}
	public PrivateKey getPrivateKey() {
		return privateKey;
	}
	public void setPrivateKey(PrivateKey privateKey) {
		this.privateKey = privateKey;
	}
	

}
