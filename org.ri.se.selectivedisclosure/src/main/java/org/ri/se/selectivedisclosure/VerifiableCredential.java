package org.ri.se.selectivedisclosure;

import java.util.Map;
import java.util.Objects;

import org.ri.se.verifiablecredentials.asymmetric.RSA2018VerifiableCredentials;

import foundation.identity.jsonld.JsonLDObject;

public class VerifiableCredential {

	private JsonLDObject jsonObj = null;

	public VerifiableCredential(String json) {
		super();
		jsonObj = JsonLDObject.fromJson(json);
	}

	public boolean verifyOffline() throws Exception {
		return new RSA2018VerifiableCredentials().verifyOffline(jsonObj.toJson(true));
	}
	public boolean verifyClaimsAttributes() throws Exception {
		if(!new RSA2018VerifiableCredentials().verifyOffline(jsonObj.toJson(true))) {
			return false;
		}
		Map<String, Object> sub = (Map<String, Object>)this.getJsonObject().get(VC.CLAIMS);
		if(Objects.isNull(sub)) {
			throw new Exception("Claims not found !");
		}
		Object subObj = sub .get(VC.ENCRYPTEDCLAIMS);
		if(!Objects.isNull(subObj)) {
			throw new Exception("Protected claims cannot be verified !");
		}
		VerifiableCredentialManager manager = new VerifiableCredentialManager();
		manager.verifyClaimsAttributes(sub, (Map<String, Object> )this.getJsonObject().get(VC.DIGEST_SET));
		
		return true;
	}
	
	public boolean verifyOnline(byte[] publickey) throws Exception {
		return new RSA2018VerifiableCredentials().verifyOnline(jsonObj.toJson(true), publickey);
	}

	public Map<String, Object> getClaims() {
		return new RSA2018VerifiableCredentials().getClaims(jsonObj.toJson(true));
	}

	public ExtendedKeyValueList getClaims(byte[] key) throws Exception {
		return new Utils().extractSecureClaims(jsonObj.toJson(true), key);
	}

	public VerifiableCredential open(byte [] key) throws Exception {
		return new VerifiableCredential(new Utils().vcWithClaims(toJson(), key));
	}
	public String toJson() {
		return jsonObj.toJson(true);
	}
	
	public String toString() {
		return jsonObj.toJson(true);
	}
	
	public Map<String, Object> getJsonObject() {
		return jsonObj.getJsonObject();
	}
	
	public JsonLDObject get() {
		return jsonObj;
	}
}