package org.acreo.security.utils;

public class CommonEnums {

	public enum KEY_USAGE{
		DIGITAL_SIGNATURE(1 << 0), 
		NON_REPUDIATION(1 << 1), 
		KEY_ENCIPHERMENT(1 << 2), 
		DATA_ENCIPHERMENT(1 << 3), 
		KEY_AGREEMENT(1 << 4), 
		KEY_CERTSIGN(1 << 5), 
		CRL_SIGN(1 << 6), 
		ENCIPHER_ONLY(1 << 7), 
		DECIPHER_ONLY(1 << 8);
		
		int keyVal = 0;
		KEY_USAGE(int keyVal){
			this.keyVal=keyVal;
		}
		public int value(){
			return keyVal;
		}
	};

	public enum CERTIFICATE_VALIDITY_STATUS {
		EXPIRED("expired"), NOT_VALID_YET("not-valid-yet"),VALID("valid");
		private String type = null;

		CERTIFICATE_VALIDITY_STATUS(String type) {
			this.type = type;

		}

		public String value() {
			return type;
		}
	};
	public enum VEIDBLOCK_STATUS {
		VALIDATED("validated"), LOCAL_VALIDATION("local-validation"), NOT_VALIDATED_YET("not-validated-yet"),REJECTED("rejected");
		private String type = null;

		VEIDBLOCK_STATUS(String type) {
			this.type = type;

		}

		public String value() {
			return type;
		}
	};

	
	
	public enum OWNER_TYPE {
		SERVER("Server"), USER("User");
		private String type = null;

		OWNER_TYPE(String type) {
			this.type = type;

		}

		public String value() {
			return type;
		}
	};

	public enum CERTIFICATE_STATUS {
		REQ_SUBMITTED("Req-submitted"), CERT_SUBMITTED("Cert-submitted"), CERT_ISSUED("Issued"), CERT_FAILED(
				"Failed"), CERT_DELETED("cert-deleted");
		private String status = null;

		CERTIFICATE_STATUS(String status) {
			this.status = status;

		}
		public String value() {
			return status;
		}
	};
	
	
	public enum PACKET_HEADER {
		DN("dn"),  CERT_REQ("cert-req"), CERT("Cert"), CERT_REPLY("Cert_Reply");
		private String value= null;

		PACKET_HEADER(String value) {
			this.value = value;

		}
		public String value() {
			return value;
		}
	};
	
	
}
