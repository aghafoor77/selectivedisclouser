package org.ri.se.verifiablecredentials.asymmetric;

import java.net.URI;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.Map;
import java.util.Objects;
import java.util.Random;

import org.apache.commons.codec.binary.Hex;
import org.ri.se.verifiablecredentials.entities.JSONLDSignatureType;
import org.ri.se.verifiablecredentials.entities.ProofAttributes;

import foundation.identity.did.DIDDocument;
import foundation.identity.did.Service;
import foundation.identity.did.VerificationMethod;
import foundation.identity.jsonld.JsonLDObject;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.signer.LdSigner;
import info.weboftrust.ldsignatures.signer.RsaSignature2018LdSigner;
import info.weboftrust.ldsignatures.verifier.RsaSignature2018LdVerifier;
import io.ipfs.multibase.Multibase;

public class RSA2018VerifiableCredentials implements IVerifiableCredentionalCreator {

	public static final String id = "RSA2018VerifiableCredentials";
	public boolean verifyOffline(String json) throws Exception {
		JsonLDObject jsonObj = new JsonLDObject();
		jsonObj = jsonObj.fromJson(json);
		Map<String, Object> map = jsonObj.toMap();
		Map<String, Object> proof = (Map<String, Object>) map.get("proof");
		for (String k : proof.keySet()) {
			if (k.toString().endsWith("Method")) {
				ArrayList<Map<String, Object>> method = (ArrayList<Map<String, Object>>) map.get(k);
				byte encoded[] = Multibase.decode(method.get(0).get("publicKeyMultibase").toString());
				if (Objects.isNull(encoded)) {
					throw new Exception(
							"Public key is not in publicKeyMultibase format. Current verson only support publicKeyMultibase !");
				}
				PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(encoded));
				RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
				RsaSignature2018LdVerifier verifier = new RsaSignature2018LdVerifier(rsaPublicKey);
				return verifier.verify(jsonObj);
			}
		}
		throw new Exception("Undefined proof method !");
	}

	public boolean verifyOnline(String json, byte[] publickey) throws Exception {
		JsonLDObject jsonObj = new JsonLDObject();
		jsonObj = jsonObj.fromJson(json);
		Map<String, Object> map = jsonObj.toMap();
		PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publickey));
		RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
		RsaSignature2018LdVerifier verifier = new RsaSignature2018LdVerifier(rsaPublicKey);
		return verifier.verify(jsonObj);
	}

	public String create(URI did, Service service, String verificatioKeyURI, JsonLDObject baseJson,
			Map<String, Object> properties, byte[] privatekey, byte[] publickey, ProofAttributes proofAtt)
			throws Exception {
		DIDDocument didDocument = preprocessing(did, service, verificatioKeyURI, baseJson, properties,
				JSONLDSignatureType.RsaSignature2018, privatekey, publickey);
		return rsaSignature2018ProofCreator(privatekey, proofAtt, didDocument);
	}

	private String rsaSignature2018ProofCreator(byte[] encodedPrivateKey, ProofAttributes proofAtt,
			DIDDocument diddoc) throws Exception {
		try {

			EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
			KeyFactory generator = KeyFactory.getInstance("RSA");
			PrivateKey privateKey = generator.generatePrivate(privateKeySpec);

			JsonLDObject jsonLdObject = JsonLDObject.fromJson(diddoc.toJson(true));
			RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) privateKey;

			LdSigner signer = new RsaSignature2018LdSigner(rsaPrivateKey);
			signer.setCreated(new Date());
			signer.setProofPurpose(proofAtt.getPurpose());
			signer.setVerificationMethod(URI.create(proofAtt.getVerificationMethod()));
			signer.setDomain(proofAtt.getDomain());
			double dub = new Random().nextDouble();
			String temp = Double.toHexString(dub);
			signer.setNonce(Hex.encodeHexString(temp.getBytes()));

			LdProof ldProof = signer.sign(jsonLdObject);
			return jsonLdObject.toJson(true);

		} catch (Exception e) {
			throw new Exception(e);
		}
	}

	private DIDDocument preprocessing(URI did, Service service, String verificatioKeyURI, JsonLDObject baseJson,
			Map<String, Object> properties, JSONLDSignatureType jsonSignatureType, byte[] privatekey,
			byte[] publickey) {

		String encoded = Multibase.encode(Multibase.Base.Base58BTC, publickey);
		VerificationMethod verificationMethod = VerificationMethod.builder().id(URI.create(verificatioKeyURI))
				.type(jsonSignatureType.getScheme()).publicKeyMultibase(encoded).build();
		

		DIDDocument diddoc = DIDDocument.builder().id(did).service(service).verificationMethod(verificationMethod)
				.properties(properties).base(baseJson).build();
		return diddoc;
	}
	
	public Map<String, Object> getClaims(String json) {
		JsonLDObject jsonObj = new JsonLDObject();
		jsonObj = jsonObj.fromJson(json);
		Map<String, Object> map = jsonObj.toMap();
		Map<String, Object> subject = (Map<String, Object>) map.get("claims");
		return subject;
	}
}
