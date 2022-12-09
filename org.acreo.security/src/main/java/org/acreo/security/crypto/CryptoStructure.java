package org.acreo.security.crypto;

public class CryptoStructure {
	public enum ENCODING_DECODING_SCHEME {
		BASE64("BASE64"), HEX("HEX"), NONE("NONE");
		private String value;

		ENCODING_DECODING_SCHEME(String value) {
			this.value = value;
		}

		public String value() {
			return value;
		}
	};

	public enum HASH_ALGO {
		MD5("MD-5"), SHA3_224("SHA-224"), SHA3_256("SHA-256"), SHA3_384("SHA-384"), SHA3_512("SHA-512");

		private String hashAlgo;

		HASH_ALGO(String hashAlgo) {
			this.hashAlgo = hashAlgo;
		}

		public String value() {
			return hashAlgo;
		}
	}
}
