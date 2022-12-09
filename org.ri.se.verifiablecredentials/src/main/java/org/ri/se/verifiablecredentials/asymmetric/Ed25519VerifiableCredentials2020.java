package org.ri.se.verifiablecredentials.asymmetric;

import java.net.URI;
import java.util.ArrayList;
import java.util.Date;
import java.util.Map;
import java.util.Objects;
import java.util.Random;

import org.apache.commons.codec.binary.Hex;
import org.ri.se.verifiablecredentials.entities.JSONLDSignatureType;
import org.ri.se.verifiablecredentials.entities.ProofAttributes;

import com.danubetech.keyformats.crypto.provider.Ed25519Provider;
import com.danubetech.keyformats.crypto.provider.RandomProvider;
import com.danubetech.keyformats.crypto.provider.SHA256Provider;
import com.danubetech.keyformats.crypto.provider.impl.JavaRandomProvider;
import com.danubetech.keyformats.crypto.provider.impl.JavaSHA256Provider;
import com.danubetech.keyformats.crypto.provider.impl.TinkEd25519Provider;

import foundation.identity.did.DIDDocument;
import foundation.identity.did.Service;
import foundation.identity.did.VerificationMethod;
import foundation.identity.jsonld.JsonLDObject;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.signer.Ed25519Signature2020LdSigner;
import info.weboftrust.ldsignatures.signer.LdSigner;
import info.weboftrust.ldsignatures.verifier.Ed25519Signature2020LdVerifier;
import io.ipfs.multibase.Multibase;

public class Ed25519VerifiableCredentials2020 implements IVerifiableCredentionalCreator {

	public Ed25519VerifiableCredentials2020() {
		RandomProvider.set(new JavaRandomProvider());
		SHA256Provider.set(new JavaSHA256Provider());
		Ed25519Provider.set(new TinkEd25519Provider());
	}

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
				Ed25519Signature2020LdVerifier verifier = new Ed25519Signature2020LdVerifier(encoded);
				boolean verify = verifier.verify(jsonObj);
				System.out.println(verify);
				return verify;
			}
		}
		throw new Exception("Undefined proof method !");
	}

	public String create(URI did, Service service, String verificatioKeyURI, JsonLDObject baseJson,
			Map<String, Object> properties, byte[] privatekey, byte[] publickey, ProofAttributes proofAtt)
			throws Exception {
		DIDDocument didDocument = preprocessing(did, service, verificatioKeyURI, baseJson, properties,
				JSONLDSignatureType.Ed25519Signature2020, privatekey, publickey);
		return ed25519Y2020ProofCreator(privatekey, proofAtt, didDocument);
	}

	private String ed25519Y2020ProofCreator(byte[] encodedPrivateKey, ProofAttributes proofAtt, DIDDocument diddoc)
			throws Exception {
		try {

			JsonLDObject jsonLdObject = JsonLDObject.fromJson(diddoc.toJson(true));

			LdSigner signer = new Ed25519Signature2020LdSigner(encodedPrivateKey);

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

	public boolean verifyOnline(String json, byte[] publickey) throws Exception {

		JsonLDObject jsonObj = new JsonLDObject();
		jsonObj = jsonObj.fromJson(json);

		Ed25519Signature2020LdVerifier verifier = new Ed25519Signature2020LdVerifier(publickey);
		boolean verify = verifier.verify(jsonObj);
		System.out.println(verify);
		return verify;

	}
}
