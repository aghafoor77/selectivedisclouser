package org.ri.se.selectivedisclosure;

public class SecureClaims {
	private String encryptedClaims;
	private String didcom;
	private String encoding;
	private String type;

	public String getEncryptedClaims() {
		return encryptedClaims;
	}

	public void setEncryptedClaims(String encryptedClaims) {
		this.encryptedClaims = encryptedClaims;
	}

	public String getDidcom() {
		return didcom;
	}

	public void setDidcom(String didcom) {
		this.didcom = didcom;
	}

	public String getEncoding() {
		return encoding;
	}

	public void setEncoding(String encoding) {
		this.encoding = encoding;
	}

	public String getType() {
		return type;
	}

	public void setType(String type) {
		this.type = type;
	}
}
