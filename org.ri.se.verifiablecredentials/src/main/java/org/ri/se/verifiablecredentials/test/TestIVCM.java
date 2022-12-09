package org.ri.se.verifiablecredentials.test;

import java.io.File;
import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Vector;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.ri.se.verifiablecredentials.asymmetric.Ed25519VerifiableCredentials2020;
import org.ri.se.verifiablecredentials.asymmetric.RSA2018VerifiableCredentials;
import org.ri.se.verifiablecredentials.entities.ProofAttributes;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.WalletUtils;

import foundation.identity.did.jsonld.DIDKeywords;
import foundation.identity.jsonld.JsonLDObject;
import info.weboftrust.ldsignatures.jsonld.LDSecurityKeywords;

public class TestIVCM {

	public static void main(String[] args) throws Exception {
		//IVerifiableCredentionalManager iverifiableCredentionalManager = new RSA2018VerifiableCredentials();
		System.out.println("=====================RSA2018VerifiableCredentials=====================");
		testRSA2018VerifiableCredentials();
		System.out.println("=====================Ed25519VerifiableCredentials2020=====================");
		testEd25519VerifiableCredentials2020();
	}

	public static void testRSA2018VerifiableCredentials() throws Exception {

		KeyPair keyPair = null;

		try {
			String algorithm = "RSA";
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algorithm);
			keyGen.initialize(2048);
			keyPair = keyGen.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		URI did = URI.create("did:ex:1234");

		byte[] data = keyPair.getPublic().getEncoded();

		JsonLDObject baseJson = new JsonLDObject();
		baseJson.setJsonObjectKeyValue("name", "am i owner");
		Vector<String> vec = new Vector();
		vec.add("VerifiableCredentialRoleRequest");
		baseJson.setJsonObjectKeyValue("type", vec);

		JsonLDObject subProps = new JsonLDObject();
		subProps.setJsonObjectKeyValue("KEY1", "{\'VALUE\'=\'sdsdsd\'}");
		Map<String, Object> properties = new HashMap<String, Object>();
		properties.put("vcRoleRequestSubject", subProps);

		ProofAttributes proofAtt = new ProofAttributes();
		proofAtt.setDomain("http://schema.org");
		proofAtt.setVerificationMethod("http://www.veidblock.com/verificationmethod");
		proofAtt.setPurpose(DIDKeywords.JSONLD_TERM_KEYAGREEMENT);

		RSA2018VerifiableCredentials rsaVerifiableCredentials = new RSA2018VerifiableCredentials();
		String json = rsaVerifiableCredentials.create(did, null, "did:eth:acctid#key1", baseJson, properties,
				keyPair.getPrivate().getEncoded(), keyPair.getPublic().getEncoded(), proofAtt);

		System.out.println(json);
		System.err.println("Verification Result :"+rsaVerifiableCredentials.verifyOffline(json));
		
	}

	public static void testEd25519VerifiableCredentials2020() throws Exception {

		Provider provider = Security.getProvider("BC");
		SecureRandom RANDOM = new SecureRandom();
		Ed25519KeyPairGenerator keyPairGenerator = new Ed25519KeyPairGenerator();
		keyPairGenerator.init(new Ed25519KeyGenerationParameters(RANDOM));
		AsymmetricCipherKeyPair asymmetricCipherKeyPair = keyPairGenerator.generateKeyPair();
		Ed25519PrivateKeyParameters privateKey = (Ed25519PrivateKeyParameters) asymmetricCipherKeyPair.getPrivate();
		Ed25519PublicKeyParameters publicKey = (Ed25519PublicKeyParameters) asymmetricCipherKeyPair.getPublic();

		byte[] ed25519PrivateKey2 = new byte[privateKey.getEncoded().length + publicKey.getEncoded().length];

		System.arraycopy(privateKey.getEncoded(), 0, ed25519PrivateKey2, 0, privateKey.getEncoded().length);
		System.arraycopy(publicKey.getEncoded(), 0, ed25519PrivateKey2, privateKey.getEncoded().length,
				publicKey.getEncoded().length);

		URI did = URI.create("did:ex:1234");

		JsonLDObject baseJson = new JsonLDObject();
		baseJson.setJsonObjectKeyValue("name", "am i owner");
		Vector<String> vec = new Vector();
		vec.add("VerifiableCredentialRoleRequest");
		baseJson.setJsonObjectKeyValue("type", vec);

		JsonLDObject subProps = new JsonLDObject();
		subProps.setJsonObjectKeyValue("KEY1", "{\'VALUE\'=\'sdsdsd\'}");
		Map<String, Object> properties = new HashMap<String, Object>();
		properties.put("vcRoleRequestSubject", subProps);

		ProofAttributes proofAtt = new ProofAttributes();
		proofAtt.setDomain("http://schema.org");
		proofAtt.setVerificationMethod("http://www.veidblock.com/verificationmethod");
		proofAtt.setPurpose(LDSecurityKeywords.JSONLD_TERM_VERIFICATIONMETHOD);
		Ed25519VerifiableCredentials2020 ed25519VerifiableCredentials2020 = new Ed25519VerifiableCredentials2020();
		String json = ed25519VerifiableCredentials2020.create(did, null, "did:eth:acctid#key1", baseJson, properties,
				ed25519PrivateKey2, publicKey.getEncoded(), proofAtt);

		System.out.println(json);
		System.err.println("Verification Result :"+ ed25519VerifiableCredentials2020.verifyOffline(json));

	
	}
	public static Credentials createAccount(String username, String password) throws Exception {
		try {

			String homeDir = System.getProperty("user.home");
			File dir = new File(homeDir + File.separator + "veidblock_RT" + File.separator + "credentials"
					+ File.separator + username);
			if (!dir.exists())
				dir.mkdirs();

			String userDir = dir.getAbsolutePath();
			String path = "";

			if (Objects.isNull(new File(userDir).list()) || new File(userDir).list().length == 0) {

				path = WalletUtils.generateNewWalletFile(password, new File(userDir), true);
			} else {
				File fl[] = new File(userDir).listFiles();
				for (File f : fl) {
					if (f.getName().endsWith(".json")) {
						path = f.getName();
					}
				}
			}
			Credentials credentials = WalletUtils.loadCredentials(password, userDir + "/" + path);
			return credentials;

		} catch (Exception e) {
			System.err.println("===> Problems when creating credentials !");
			System.err.println(e.getMessage());
			throw new Exception(e);
		}
	}
	
}
