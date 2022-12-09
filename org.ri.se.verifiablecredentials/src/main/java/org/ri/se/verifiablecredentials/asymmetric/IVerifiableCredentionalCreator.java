package org.ri.se.verifiablecredentials.asymmetric;

import java.net.URI;
import java.util.Map;

import org.ri.se.verifiablecredentials.entities.ProofAttributes;

import foundation.identity.did.Service;
import foundation.identity.jsonld.JsonLDObject;

public interface IVerifiableCredentionalCreator {

	public String create(URI did, Service service, String verificatioKeyURI, JsonLDObject baseJson,
			Map<String, Object> properties, byte[] privatekey, byte[] publickey, ProofAttributes proofAtt)
			throws Exception;
	public boolean verifyOnline(String json, byte[] publickey) throws Exception;
	public boolean verifyOffline(String json) throws Exception;
}
