/**
 * 
 */
package org.ri.se.selectivedisclosure.security;

/**
 * @author blockchain
 *
 */
public enum SecurityContext {
	AES256("AES256"), AES192("AES192"), AES128("AES128"), DES("DES"), PRIVACY("PRIVACY"), NONE("NONE");

	SecurityContext(String value) {
		this.value = value;
	}

	private final String value;

	public String value() {
		return value;
	}
}
