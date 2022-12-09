package org.ri.se.verifiablecredentials.asymmetric;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import java.util.Objects;

import javax.xml.bind.DatatypeConverter;

import org.bitcoinj.core.ECKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.WalletUtils;

import foundation.identity.jsonld.JsonLDObject;
import foundation.identity.jsonld.JsonLDUtils;
import info.weboftrust.ldsignatures.LdProof;
import info.weboftrust.ldsignatures.jsonld.LDSecurityContexts;
import info.weboftrust.ldsignatures.signer.EcdsaSecp256k1Signature2019LdSigner;
import info.weboftrust.ldsignatures.verifier.EcdsaSecp256k1Signature2019LdVerifier;

public class EcdsaSecp256k1VerifiableCredentials2019 {


	
	public static void main(String arg[]) throws Throwable {
		
		Security.addProvider(new BouncyCastleProvider());
		new EcdsaSecp256k1VerifiableCredentials2019().testSignEcdsaSecp256k1Signature2019();
	}
	
	public Credentials createAccount(String username, String password) throws Exception {
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
	public static KeyPair creteKey() throws Exception {
		 KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDSA", "BC");
	        ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec("secp256k1");
	        SecureRandom random = new SecureRandom();
	        if (random != null) {
	            keyPairGenerator.initialize(ecGenParameterSpec, random);
	        } else {
	            keyPairGenerator.initialize(ecGenParameterSpec);
	        }
	        return keyPairGenerator.generateKeyPair();
	}
	public void testSignEcdsaSecp256k1Signature2019() throws Throwable {

		
		Credentials cred = createAccount("exp","exp");
		ECKey ec1 = ECKey.fromPrivate(cred.getEcKeyPair().getPrivateKey());
		System.out.println("========================== 1");
		
		System.out.println(cred.getEcKeyPair().getPublicKey().toByteArray().length);
		System.out.println(cred.getAddress().getBytes().length);
		System.out.println(cred.getAddress());
		ECKey ecPub1 = ECKey.fromPublicOnly(DatatypeConverter.parseHexBinary(cred.getAddress().substring(2)));
		System.out.println("========================== 2");
		
		boolean bol = true;
		if(bol) {
			return;
		}
		
		JsonLDObject jsonLdObject = JsonLDObject.fromJson(new InputStreamReader( new FileInputStream("/home/ag/Desktop/RISE/development/traceability/org.ri.se.did/src/main/resources/input.jsonld")));
		jsonLdObject.setDocumentLoader(LDSecurityContexts.DOCUMENT_LOADER);

		URI creator = URI.create("did:sov:WRfXPg8dantKVubE3HX8pw");
		Date created = JsonLDUtils.DATE_FORMAT.parse("2017-10-24T05:33:31Z");
		String domain = "example.com";
		String nonce = null;

		
		KeyPair kpRaw = creteKey();
		ECKeyPair kp = ECKeyPair.create(kpRaw);
		ECKey ec = ECKey.fromPrivate(kp.getPrivateKey());
		System.out.println("========================== 1");
		
		EcdsaSecp256k1Signature2019LdSigner signer = new EcdsaSecp256k1Signature2019LdSigner(ec);
		signer.setCreator(creator);
		signer.setCreated(created);
		signer.setDomain(domain);
		signer.setNonce(nonce);
		LdProof ldProof = signer.sign(jsonLdObject);
		System.out.println("========================== 1.1");
		ECKey ecPub = ECKey.fromPublicOnly(kpRaw.getPublic().getEncoded());
		System.out.println("========================== 2");
		
		EcdsaSecp256k1Signature2019LdVerifier verifier = new EcdsaSecp256k1Signature2019LdVerifier(ecPub);
		boolean verify = verifier.verify(jsonLdObject, ldProof);
		System.out.println(verify);
	}


}
