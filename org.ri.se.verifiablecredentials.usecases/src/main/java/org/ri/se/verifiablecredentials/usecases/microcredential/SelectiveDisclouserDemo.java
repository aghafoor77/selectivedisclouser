package org.ri.se.verifiablecredentials.usecases.microcredential;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import org.ri.se.selectivedisclosure.RSAAsymmetricKeyPair;
import org.ri.se.selectivedisclosure.Utils;
import org.ri.se.selectivedisclosure.VC;
import org.ri.se.selectivedisclosure.VerifiableCredential;
import org.ri.se.selectivedisclosure.VerifiableCredentialManager;
import org.ri.se.selectivedisclosure.VerifiablePresentation;
import org.ri.se.selectivedisclosure.security.CryptoProcessor;
import org.ri.se.selectivedisclosure.security.SecurityContext;

/**
 * 
 * @author Abdul Ghafoor abdul.ghafoor@ri.se Main class to demonstrate the
 *         concept of selective disclouser
 *
 */
public class SelectiveDisclouserDemo {

	public static PublicKey vcCreatorPublicKey;
	public static PublicKey vcPresentorPublicKey;
	public static PublicKey envelopedvcCreatorPublicKey;
	public static PublicKey envelopedVCPresentorPublicKey;

	/**
	 * 
	 * @param args : commandline argument
	 * @throws Exception
	 */
	public static void main(String[] args) throws Exception {

		new SelectiveDisclouserDemo().demos();
	}

	public String createMicrocredentialVC() throws Exception {

		// Claims of the verifiable credentials
		Map<String, Object> subjectData = new HashMap<String, Object>();

		String holder = "0x71aD1108403C28f3723d09D533337BC115528039";
		String controller = "0xC5B09bb75A2C4b6Bb0c91E9dac4d3cC3C40Fed05";

		controller = VC.PREID + controller;
		holder = VC.PREID + holder;
		SDSubject sdSubject = new SDSubject();
		SimpleDateFormat formatter = new SimpleDateFormat("dd/MM/yyyy", Locale.ENGLISH);

		sdSubject.setAddress("UV, Stockholm");
		sdSubject.setName("Abdul Ghafoor");
		sdSubject.setDateofBirth(formatter.parse("08/02/1988"));
		sdSubject.setDrivingLicenceNo("SE12212349786");
		sdSubject.setSocialSecuirtyNumber("3473970SE88989STM");
		sdSubject.setVehicleType("Car");
		sdSubject.setIssueDate(formatter.parse("12/03/2022"));
		sdSubject.setExpiryDate(formatter.parse("13/03/2027"));

		subjectData.put(SDSubjectHeader.ADDRESS.getValue(), sdSubject.getAddress());
		subjectData.put(SDSubjectHeader.DATEOFBIRTH.getValue(), sdSubject.getDateofBirth());
		subjectData.put(SDSubjectHeader.DRIVINGLICENCENO.getValue(), sdSubject.getDrivingLicenceNo());
		subjectData.put(SDSubjectHeader.EXPIRYDATE.getValue(), sdSubject.getExpiryDate());
		subjectData.put(SDSubjectHeader.ISSUEDATE.getValue(), sdSubject.getIssueDate());
		subjectData.put(SDSubjectHeader.NAME.getValue(), sdSubject.getName());
		subjectData.put(SDSubjectHeader.SOCIALSECURITYNUBER.getValue(), sdSubject.getSocialSecuirtyNumber());
		subjectData.put(SDSubjectHeader.VEHIVLETYPE.getValue(), sdSubject.getVehicleType());

		// Generate a RSA Asymmetric key for VC
		VerifiableCredentialManager credentialManager = new VerifiableCredentialManager();
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(2048);
		KeyPair pair = keyGen.generateKeyPair();
		PrivateKey privateKey = pair.getPrivate();
		vcCreatorPublicKey = pair.getPublic();
		RSAAsymmetricKeyPair keyPair = new RSAAsymmetricKeyPair(vcCreatorPublicKey, privateKey);

		// Creating VC
		VerifiableCredential jsonVC = credentialManager.create(controller, keyPair, subjectData, holder);
		String json = jsonVC.toJson();

		// Extracting claims from VC
		String toStore = new Utils().vcWithClaims(json);
		return toStore;
	}

	public VerifiablePresentation verifiablePresentation(String toStore, ArrayList<String> requestedItems)
			throws Exception {

		VerifiableCredentialManager manager = new VerifiableCredentialManager();
		// Generate a RSA Asymmetric key for Verifiable Presentation
		VerifiableCredentialManager credentialManager = new VerifiableCredentialManager();
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(2048);
		KeyPair pair = keyGen.generateKeyPair();
		PrivateKey privateKey = pair.getPrivate();
		vcPresentorPublicKey = pair.getPublic();
		RSAAsymmetricKeyPair keyPair = new RSAAsymmetricKeyPair(vcPresentorPublicKey, privateKey);

		String verifier = "0xD80669C93d46c17ba45C89bc7A450148C81a90F7";
		verifier = VC.PREID + verifier;
		// Creating verifiable presentation for requestedItems
		VerifiablePresentation vp = manager.createVerifiablePresentation(toStore, verifier, requestedItems, keyPair);
		return vp;
	}

	public String createEnvelopedMicrocredentialVC() throws Exception {

		Map<String, Object> subjectData = new HashMap<String, Object>();

		String holder = "0x71aD1108403C28f3723d09D533337BC115528039";
		String controller = "0xC5B09bb75A2C4b6Bb0c91E9dac4d3cC3C40Fed05";

		controller = VC.PREID + controller;
		holder = VC.PREID + holder;

		// Attributes for claims
		SDSubject sdSubject = new SDSubject();
		SimpleDateFormat formatter = new SimpleDateFormat("dd/MM/yyyy", Locale.ENGLISH);

		sdSubject.setAddress("UV, Stockholm");
		sdSubject.setName("Abdul Ghafoor");
		sdSubject.setDateofBirth(formatter.parse("08/02/1988"));
		sdSubject.setDrivingLicenceNo("SE12212349786");
		sdSubject.setSocialSecuirtyNumber("3473970SE88989STM");
		sdSubject.setVehicleType("Car");
		sdSubject.setIssueDate(formatter.parse("12/03/2022"));
		sdSubject.setExpiryDate(formatter.parse("13/03/2027"));

		subjectData.put(SDSubjectHeader.ADDRESS.getValue(), sdSubject.getAddress());
		subjectData.put(SDSubjectHeader.DATEOFBIRTH.getValue(), sdSubject.getDateofBirth());
		subjectData.put(SDSubjectHeader.DRIVINGLICENCENO.getValue(), sdSubject.getDrivingLicenceNo());
		subjectData.put(SDSubjectHeader.EXPIRYDATE.getValue(), sdSubject.getExpiryDate());
		subjectData.put(SDSubjectHeader.ISSUEDATE.getValue(), sdSubject.getIssueDate());
		subjectData.put(SDSubjectHeader.NAME.getValue(), sdSubject.getName());
		subjectData.put(SDSubjectHeader.SOCIALSECURITYNUBER.getValue(), sdSubject.getSocialSecuirtyNumber());
		subjectData.put(SDSubjectHeader.VEHIVLETYPE.getValue(), sdSubject.getVehicleType());

		String didcom = "did:veid:Ox767389a9889b87cb8a";
		// ISSUER : Generating symmetric key for enveloped verifiable
		// credentials/presentation and it must be shared
		CryptoProcessor cryptoProcessor = new CryptoProcessor();
		byte[] key = cryptoProcessor.generateSymmetrickey(SecurityContext.AES128);
		VerifiableCredentialManager credentialManager = new VerifiableCredentialManager();

		// Generating RSA Key for enveloped VCs

		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(2048);
		KeyPair pair = keyGen.generateKeyPair();
		PrivateKey privateKey = pair.getPrivate();
		envelopedvcCreatorPublicKey = pair.getPublic();
		RSAAsymmetricKeyPair keyPair = new RSAAsymmetricKeyPair(envelopedvcCreatorPublicKey, privateKey);
		// Creating Enveloped VCs
		VerifiableCredential jsonVC = credentialManager.create(controller, keyPair, subjectData, holder, didcom, key);
		String json = jsonVC.toJson();
		System.out.println(json);

		System.in.read();
		System.err
				.println("-------------------------------------------------------------------------------------------");
		System.err.println("1.1. Openning protected microcredentials !");

		// Opening and verifying VCs
		VerifiableCredential clearVC = jsonVC.open(key);
		System.out.println(clearVC.toJson());
		return clearVC.toJson();
	}

	public VerifiablePresentation envelopedVerifiablePresentation(String toStore, ArrayList<String> requestedItems)
			throws Exception {

		VerifiableCredentialManager manager = new VerifiableCredentialManager();
		// HOLDER: Generating symmetric key for enveloped verifiable presentation and it
		// must be shared
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(2048);
		KeyPair pair = keyGen.generateKeyPair();
		PrivateKey privateKey = pair.getPrivate();
		envelopedVCPresentorPublicKey = pair.getPublic();
		RSAAsymmetricKeyPair keyPair = new RSAAsymmetricKeyPair(envelopedVCPresentorPublicKey, privateKey);

		String verifier = "0xD80669C93d46c17ba45C89bc7A450148C81a90F7";
		verifier = VC.PREID + verifier;
		System.out.println("\n");
		System.err
				.println("-------------------------------------------------------------------------------------------");
		System.err.println("3. Creating enveloped verifiable presentation !");
		System.in.read();
		String didcom = "did:veid:Ox767389a9889b87cb8a";
		CryptoProcessor cryptoProcessor = new CryptoProcessor();
		byte[] key = cryptoProcessor.generateSymmetrickey(SecurityContext.AES128);
		// Creating enveloped verifiable presentation
		VerifiablePresentation vp = manager.createVerifiablePresentation(toStore, verifier, requestedItems, keyPair,
				didcom, key);
		System.out.println(vp.toJson());
		System.in.read();
		System.err
				.println("-------------------------------------------------------------------------------------------");
		System.err.println("4. Opening enveloped verifiable presentation !");

		// Opening enveloped verifiable presentation using same symmetric key 
		VerifiablePresentation vpRec = vp.open(key);

		System.out.println(vpRec.toJson());
		System.in.read();
		System.err
				.println("-------------------------------------------------------------------------------------------");
		System.err.println("5. Verifier verifying verifiable presentation !");

		if (vpRec.verifyClaimsAttributes())
			System.out.println("Successfully verified");
		else
			System.out.println("Verification failed ");
		return vp;
	}

	public void demos() throws Exception {
		System.err.println(
				"Demo A. ======================= Verifiable Microcredential Demonstration =======================");
		{
			System.in.read();
			System.err.println(
					"-------------------------------------------------------------------------------------------");
			System.err.println("1. Creating Verifiable Credential with readable claims !");

			String mvcClear = createMicrocredentialVC();
			System.out.println(mvcClear);

			System.in.read();
			System.err.println(
					"-------------------------------------------------------------------------------------------");
			System.err.println("2. Verifying Verifiable Microcredential =======================");

			if (new VerifiableCredential(mvcClear).verifyClaimsAttributes())
				System.out.println("Successfully verified Verifiable credentials !");
			else
				System.out.println("Verification failed !");

			System.in.read();
			System.err.println(
					"-------------------------------------------------------------------------------------------");
			System.err.println("3. Creating verifiable micropresentation !");

			// Applying selective disclosure concept and selecting only two attribute to
			// present
			ArrayList<String> requestedItems1 = new ArrayList<String>();
			requestedItems1.add(SDSubjectHeader.ISSUEDATE.getValue());
			requestedItems1.add(SDSubjectHeader.EXPIRYDATE.getValue());

			VerifiablePresentation vp1 = verifiablePresentation(mvcClear, requestedItems1);
			System.out.println(vp1.toJson());

			System.in.read();
			System.err.println(
					"-------------------------------------------------------------------------------------------");
			System.err.println("4. Verifying verifiable micropresentation !");

			if (vp1.verifyClaimsAttributes())
				System.out.println("Successfully verified");
			else
				System.out.println("Verification failed ");

		}
		{

			System.in.read();
			System.err.println(
					"Demo B.======================= Creating Enveloped Verifiable Microcredential =======================");
			System.err.println(
					"-------------------------------------------------------------------------------------------");
			System.err.println("1. Creating Enveloped Verifiable Credential with protected claims !");
			ArrayList<String> requestedItems2 = new ArrayList<String>();
			requestedItems2.add(SDSubjectHeader.DRIVINGLICENCENO.getValue());
			requestedItems2.add(SDSubjectHeader.NAME.getValue());
			requestedItems2.add(SDSubjectHeader.VEHIVLETYPE.getValue());
			String mvcProtected = createEnvelopedMicrocredentialVC();

			System.in.read();
			System.err.println(
					"-------------------------------------------------------------------------------------------");
			System.err.println("1. Creating Enveloped Verifiable Preentation with protected claims !");
			VerifiablePresentation vp2 = envelopedVerifiablePresentation(mvcProtected, requestedItems2);
			System.out.println(vp2.toJson());
		}
	}
}
