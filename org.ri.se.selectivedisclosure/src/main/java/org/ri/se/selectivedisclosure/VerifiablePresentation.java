package org.ri.se.selectivedisclosure;

import java.util.Map;
import java.util.Objects;

import org.ri.se.verifiablecredentials.asymmetric.RSA2018VerifiableCredentials;

import foundation.identity.jsonld.JsonLDObject;

public class VerifiablePresentation {

	private JsonLDObject jsonObj = null;

	public VerifiablePresentation(String json) {
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
		
		
		Map<String, Object> presentation = (Map<String, Object>)this.getJsonObject().get(VC.PRESENTATION);
		if(Objects.isNull(presentation)) {
			throw new Exception("Presentation not found !");
		}
		
		Map<String, Object> sub = (Map<String, Object>)presentation.get(VC.CLAIMS);
		if(Objects.isNull(sub)) {
			throw new Exception("Claims not found !");
		}
		Object subObj = sub.get(VC.ENCRYPTEDCLAIMS);
		if(!Objects.isNull(subObj)) {
			throw new Exception("Protected claims cannot be verified !");
		}
		Map<String, Object> digest = (Map<String, Object>) presentation.get(VC.DIGEST_SET);
		if(Objects.isNull(digest)) {
			throw new Exception("Could not reterive digest-set !");
		}
			
		VerifiableCredentialManager manager = new VerifiableCredentialManager();
		
		manager.verifyClaimsAttributes(sub, digest);
		
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

	public VerifiablePresentation open(byte [] key) throws Exception {
		String temp = new Utils().vpWithClaims(toJson(), key);
		return new VerifiablePresentation(temp);
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
