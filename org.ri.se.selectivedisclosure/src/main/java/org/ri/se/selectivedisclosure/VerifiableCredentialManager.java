package org.ri.se.selectivedisclosure;

import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Objects;
import java.util.Vector;

import org.apache.commons.lang3.RandomStringUtils;
import org.ri.se.selectivedisclosure.security.CryptoProcessor;
import org.ri.se.verifiablecredentials.asymmetric.RSA2018VerifiableCredentials;
import org.ri.se.verifiablecredentials.entities.ProofAttributes;

import com.fasterxml.jackson.databind.ObjectMapper;

import foundation.identity.did.jsonld.DIDKeywords;
import foundation.identity.jsonld.JsonLDObject;

public class VerifiableCredentialManager {

	public VerifiableCredential create(String controller, RSAAsymmetricKeyPair asymmetricPair,
			Map<String, Object> claimsData, String holder, String didcom, byte[] key) throws Exception {
		ExtendedKeyValueList list = new ExtendedKeyValueList();

		String vcJson = createVerifiableCredential(controller, asymmetricPair, claimsData, list, holder, didcom);

		VerifiableCredential vc = new VerifiableCredential(new Utils().addSecureClaims(vcJson, list, didcom, key));
		return vc;
	}

	public VerifiableCredential create(String controller, RSAAsymmetricKeyPair asymmetricPair,
			Map<String, Object> claimsData, String holder) throws Exception {
		ExtendedKeyValueList list = new ExtendedKeyValueList();
		String vcJson = createVerifiableCredential(controller, asymmetricPair, claimsData, list, holder, null);

		VerifiableCredential vc = new VerifiableCredential(new Utils().addClaims(vcJson, list));
		return vc;
	}

	private String createVerifiableCredential(String controller, RSAAsymmetricKeyPair asymmetricPair,
			Map<String, Object> claimsData, ExtendedKeyValueList list, String holder, String didcom)
			throws Exception {

		// claimsData

		// Add encrypted symmetric key with key agreement tag
		// Creating credentials
		JsonLDObject baseJson = new JsonLDObject();
		baseJson.setJsonObjectKeyValue(VC.ISSUER, controller);
		baseJson.setJsonObjectKeyValue(VC.HOLDER, holder);
		Vector<String> vec = new Vector();
		vec.add(VC.VERIFIABLECREDENTIAL);
		baseJson.setJsonObjectKeyValue(VC.TYPE, vec);

		HashMap<String, String> digestList = new HashMap<String, String>();
		int i = 0;
		CryptoProcessor cryptoProcessor = new CryptoProcessor();
		for (String aDataKey : claimsData.keySet()) {
			ExtendedKeyValue enhancedKeyValue = new ExtendedKeyValue();
			String id = "c" + i;
			enhancedKeyValue.setName(aDataKey);
			enhancedKeyValue.setValue(claimsData.get(aDataKey).toString());
			enhancedKeyValue.setSalt(RandomStringUtils.randomAlphanumeric(64));
			digestList.put(id, new String(cryptoProcessor.digest(enhancedKeyValue.serialize().getBytes())));
			list.put(id, enhancedKeyValue);
			i++;
		}
		Map<String, Object> properties = new HashMap<String, Object>();
		properties.put(VC.DIGEST_SET, digestList);

		ProofAttributes proofAtt = new ProofAttributes();
		proofAtt.setDomain(VC.DOMAIN);
		proofAtt.setVerificationMethod(VC.VERIFICATIONMETHOD);
		proofAtt.setPurpose(DIDKeywords.JSONLD_TERM_VERIFICATIONMETHOD);

		// = new Utils().getPrivateKey(username, password);
		RSA2018VerifiableCredentials rsaVerifiableCredentials = new RSA2018VerifiableCredentials();
		URI uriController = Objects.isNull(didcom) ? null : new URI(didcom);
		String json = rsaVerifiableCredentials.create(uriController, null, controller + "#key1", baseJson, properties,
				asymmetricPair.getPrivateKey().getEncoded(), asymmetricPair.getPublicKey().getEncoded(), proofAtt);
		return json;
	}

	private String createVerifiablePresentation(String holder, RSAAsymmetricKeyPair asymmetricPair,
			JsonLDObject verifiablePresentatin, String presenter) throws Exception {

		// claimsData

		// Add encrypted symmetric key with key agreement tag
		// Creating credentials
		JsonLDObject baseJson = new JsonLDObject();
		baseJson.setJsonObjectKeyValue(VC.VERIFIER, presenter);
		baseJson.setJsonObjectKeyValue(VC.HOLDER, holder);
		Vector<String> vec = new Vector();
		vec.add(VC.VERIFIABLEPRESENTATION);
		baseJson.setJsonObjectKeyValue(VC.TYPE, vec);

		CryptoProcessor cryptoProcessor = new CryptoProcessor();

		Map<String, Object> properties = new HashMap<String, Object>();
		properties.put(VC.PRESENTATION, verifiablePresentatin);

		ProofAttributes proofAtt = new ProofAttributes();
		proofAtt.setDomain(VC.DOMAIN);
		proofAtt.setVerificationMethod(VC.VERIFICATIONMETHOD);
		proofAtt.setPurpose(DIDKeywords.JSONLD_TERM_VERIFICATIONMETHOD);

		// = new Utils().getPrivateKey(username, password);
		RSA2018VerifiableCredentials rsaVerifiableCredentials = new RSA2018VerifiableCredentials();
		String json = rsaVerifiableCredentials.create(null, null, holder + "#key1", baseJson, properties,
				asymmetricPair.getPrivateKey().getEncoded(), asymmetricPair.getPublicKey().getEncoded(), proofAtt);
		return json;
	}

	public VerifiablePresentation createVerifiablePresentation(String json, String presentedto,
			ArrayList<String> requestedItems, RSAAsymmetricKeyPair asymmetricPair, String didcom, byte [] key) throws Exception {

		VerifiableCredential vc = new VerifiableCredential(json);
		vc.verifyClaimsAttributes();
		
		Map<String, Object> claims = vc.getClaims();
		Iterator<String> attributes= claims.keySet().iterator();

		ExtendedKeyValueList selectedClaimsList = new ExtendedKeyValueList();
		while (attributes.hasNext()) {
			String attribute = attributes.next();
			ExtendedKeyValue ekv = new ExtendedKeyValue();
			ekv.deserialize(new ObjectMapper().writeValueAsString(claims.get(attribute)));
			if (requestedItems.contains(ekv.getName())) {
				selectedClaimsList.put(attribute, ekv);
			}
		}

		JsonLDObject jsonObj = new JsonLDObject();
		jsonObj = jsonObj.fromJson(json);
		Map<String, Object> map = jsonObj.toMap();
		map.remove(VC.CLAIMS);
		String vcJson = new ObjectMapper().writeValueAsString(map);
		jsonObj = jsonObj.fromJson(vcJson);
		
		String jsonUpdated = new Utils().addSecureClaims(vcJson, selectedClaimsList, didcom, key);

		VerifiableCredential credential = new VerifiableCredential(jsonUpdated);
		String holder = map.get(VC.HOLDER).toString();

		String vcUp = createVerifiablePresentation(holder, asymmetricPair, credential.get(), presentedto);
		return new VerifiablePresentation(vcUp);
	
		
	}
	public VerifiablePresentation createVerifiablePresentation(String json, String presentedto,
			ArrayList<String> requestedItems, RSAAsymmetricKeyPair asymmetricPair) throws Exception {

		
		VerifiableCredential vc = new VerifiableCredential(json);
		vc.verifyClaimsAttributes();
		
		Map<String, Object> claims = vc.getClaims();
		Iterator<String> keys = claims.keySet().iterator();

		ExtendedKeyValueList selectedClaimsList = new ExtendedKeyValueList();
		while (keys.hasNext()) {
			String key = keys.next();
			ExtendedKeyValue ekv = new ExtendedKeyValue();
			ekv.deserialize(new ObjectMapper().writeValueAsString(claims.get(key)));
			if (requestedItems.contains(ekv.getName())) {
				selectedClaimsList.put(key, ekv);
			}
		}

		JsonLDObject jsonObj = new JsonLDObject();
		jsonObj = jsonObj.fromJson(json);
		Map<String, Object> map = jsonObj.toMap();
		map.remove(VC.CLAIMS);
		String vcJson = new ObjectMapper().writeValueAsString(map);
		jsonObj = jsonObj.fromJson(vcJson);
		
		String jsonUpdated = new Utils().addClaims(jsonObj.toJson(true), selectedClaimsList);
		VerifiableCredential credential = new VerifiableCredential(jsonUpdated);
		String holder = map.get(VC.HOLDER).toString();

		String vcUp = createVerifiablePresentation(holder, asymmetricPair, credential.get(), presentedto);
		return new VerifiablePresentation(vcUp);
	}

	public boolean verifyClaimsAttributes(Map<String, Object> claims, Map<String, Object> digest) throws Exception {
		
		Iterator<String> keys = claims.keySet().iterator();
		CryptoProcessor cryptoProcessor = new CryptoProcessor();
		while (keys.hasNext()) {
			String key = keys.next();
			ExtendedKeyValue ekv = new ExtendedKeyValue();
			ekv.deserialize(new ObjectMapper().writeValueAsString(claims.get(key)));
			String hahsValue = digest.get(key).toString();
			if (!cryptoProcessor.verify(ekv.serialize().getBytes(), hahsValue.getBytes())) {
				throw new Exception("Verification of claims failed !");
			}
		}
		return true;
	}
}