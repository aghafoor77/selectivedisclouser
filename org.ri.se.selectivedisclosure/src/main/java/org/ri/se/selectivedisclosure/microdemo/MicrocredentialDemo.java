package org.ri.se.selectivedisclosure.microdemo;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import org.ri.se.selectivedisclosure.RSAAsymmetricKeyPair;
import org.ri.se.selectivedisclosure.Utils;
import org.ri.se.selectivedisclosure.VC;
import org.ri.se.selectivedisclosure.VerifiableCredential;
import org.ri.se.selectivedisclosure.VerifiableCredentialManager;
import org.ri.se.selectivedisclosure.VerifiablePresentation;
import org.ri.se.selectivedisclosure.security.CryptoProcessor;
import org.ri.se.selectivedisclosure.security.SecurityContext;

public class MicrocredentialDemo {

	public static void main(String[] args) throws Exception {

		new MicrocredentialDemo().presentationDemos();
	}

	public String createMicrocredentialVC() throws Exception {

		String walletDir = "/home/ag/Desktop/RISE/development/traceability/org.ri.se.trace.test/src/main/resources";
		String username0 = "abdul0";
		String password0 = "1122334455";

		Map<String, Object> subjectData = new HashMap<String, Object>();

		String holder = "0x71aD1108403C28f3723d09D533337BC115528039";
		String controller = "0xC5B09bb75A2C4b6Bb0c91E9dac4d3cC3C40Fed05";

		controller = VC.PREID + controller;
		holder = VC.PREID + holder;

		subjectData.put(Microcredential.holder, holder); // identification of the learner
		subjectData.put(Microcredential.label, "Big data");// (2) title of the micro-credential
		subjectData.put(Microcredential.issueraddress, "RISE AB, Kista");// (3) country/Region of the issuer
		subjectData.put(Microcredential.awardingBody, "RISE AB");// (4) awarding body
		subjectData.put(Microcredential.dataeofIssuing, "20220722");// (5) date of issuing
		subjectData.put(Microcredential.learningOutcomes, "To userstand the basics of Big data ");// (6) learning
																									// outcomes
		subjectData.put(Microcredential.workload, "8 hrs");// (7) notional workload needed to achieve the learning
															// outcomes (in European Credit Transfer and Accumulation
															// System, wherever possible)
		subjectData.put(Microcredential.cycle, "1");// (8) level (and cycle, if applicable) of the learning experience
													// leading to the micro-credential (European Qualifications
													// Framework, Qualifications Frameworks in the European Higher
													// Education Area), if applicable
		subjectData.put(Microcredential.typeOfAssesment, "Assignment");// (9) type of assessment
		subjectData.put(Microcredential.participationForm, "Online");// (10) form of participation in the learning
																		// activity
		subjectData.put(Microcredential.typeOfQaulityAssurance, "not clear to me");// (11) type of quality assurance
																					// used to underpin the
																					// micro-credential
		// Optional
		subjectData.put(Microcredential.expirydate, "20250721");// (12) date of expiring

		String didcom = "did:veid:Ox767389a9889b87cb8a";
		CryptoProcessor cryptoProcessor = new CryptoProcessor();
		byte[] key = cryptoProcessor.generateSymmetrickey(SecurityContext.AES128);
		VerifiableCredentialManager credentialManager = new VerifiableCredentialManager();
		RSAAsymmetricKeyPair keyPair = new Utils().getPrivateKey(username0, password0);

		VerifiableCredential jsonVC = credentialManager.create(controller, keyPair, subjectData, holder);
		String json = jsonVC.toJson();

		String toStore = new Utils().vcWithClaims(json);
		return toStore;
	}

	public VerifiablePresentation verifiablePresentation(String toStore, ArrayList<String> requestedItems)
			throws Exception {
		VerifiableCredentialManager manager = new VerifiableCredentialManager();
		String walletDir = "/home/ag/Desktop/RISE/development/traceability/org.ri.se.trace.test/src/main/resources";
		String username0 = "abdul0";
		String password0 = "1122334455";
		RSAAsymmetricKeyPair keyPair = new Utils().getPrivateKey(username0, password0);
		String verifier = "0xD80669C93d46c17ba45C89bc7A450148C81a90F7";
		verifier = VC.PREID + verifier;
		VerifiablePresentation vp = manager.createVerifiablePresentation(toStore, verifier, requestedItems, keyPair);
		return vp;
	}

	public String createEnvelopedMicrocredentialVC() throws Exception {

		String walletDir = "/home/ag/Desktop/RISE/development/traceability/org.ri.se.trace.test/src/main/resources";
		String username0 = "abdul0";
		String password0 = "1122334455";

		Map<String, Object> subjectData = new HashMap<String, Object>();

		String holder = "0x71aD1108403C28f3723d09D533337BC115528039";
		String controller = "0xC5B09bb75A2C4b6Bb0c91E9dac4d3cC3C40Fed05";

		controller = VC.PREID + controller;
		holder = VC.PREID + holder;

		subjectData.put(Microcredential.holder, holder); // identification of the learner
		subjectData.put(Microcredential.label, "Big data");// (2) title of the micro-credential
		subjectData.put(Microcredential.issueraddress, "RISE AB, Kista");// (3) country/Region of the issuer
		subjectData.put(Microcredential.awardingBody, "RISE AB");// (4) awarding body
		subjectData.put(Microcredential.dataeofIssuing, "20220722");// (5) date of issuing
		subjectData.put(Microcredential.learningOutcomes, "To understand the basics of Big data ");// (6) learning
																									// outcomes
		subjectData.put(Microcredential.workload, "8 hrs");// (7) notional workload needed to achieve the learning
															// outcomes (in European Credit Transfer and Accumulation
															// System, wherever possible)
		subjectData.put(Microcredential.cycle, "1");// (8) level (and cycle, if applicable) of the learning experience
													// leading to the micro-credential (European Qualifications
													// Framework, Qualifications Frameworks in the European Higher
													// Education Area), if applicable
		subjectData.put(Microcredential.typeOfAssesment, "Assignment");// (9) type of assessment
		subjectData.put(Microcredential.participationForm, "Online");// (10) form of participation in the learning
																		// activity
		subjectData.put(Microcredential.typeOfQaulityAssurance, "not clear to me");// (11) type of quality assurance
																					// used to underpin the
																					// micro-credential
		// Optional
		subjectData.put(Microcredential.expirydate, "20250721");// (12) date of expiring

		String didcom = "did:veid:Ox767389a9889b87cb8a";
		CryptoProcessor cryptoProcessor = new CryptoProcessor();
		byte[] key = cryptoProcessor.generateSymmetrickey(SecurityContext.AES128);
		VerifiableCredentialManager credentialManager = new VerifiableCredentialManager();
		RSAAsymmetricKeyPair keyPair = new Utils().getPrivateKey(username0, password0);

		VerifiableCredential jsonVC = credentialManager.create(controller, keyPair, subjectData, holder, didcom, key);
		String json = jsonVC.toJson();
		System.out.println(json);
		System.out.println("Press enter to continue !");
		System.in.read();
		System.err
				.println("-------------------------------------------------------------------------------------------");
		System.err.println("1.1. [Holder] Openning protected microcredentials !");

		VerifiableCredential clearVC = jsonVC.open(key);
		System.out.println(clearVC.toJson());
		return clearVC.toJson();
	}

	public VerifiablePresentation envelopedVerifiablePresentation(String toStore, ArrayList<String> requestedItems)
			throws Exception {

		VerifiableCredentialManager manager = new VerifiableCredentialManager();
		String walletDir = "/home/ag/Desktop/RISE/development/traceability/org.ri.se.trace.test/src/main/resources";
		String username0 = "abdul0";
		String password0 = "1122334455";
		RSAAsymmetricKeyPair keyPair = new Utils().getPrivateKey(username0, password0);
		String verifier = "0xD80669C93d46c17ba45C89bc7A450148C81a90F7";
		verifier = VC.PREID + verifier;
		System.out.println("\n");
		System.err
				.println("-------------------------------------------------------------------------------------------");
		System.err.println("3. [Holder] Creating enveloped verifiable presentation !");
		System.out.println("Press enter to continue !");
		System.in.read();
		String didcom = "did:veid:Ox767389a9889b87cb8a";
		CryptoProcessor cryptoProcessor = new CryptoProcessor();
		byte[] key = cryptoProcessor.generateSymmetrickey(SecurityContext.AES128);
		System.out.println("======= Verifier requested following items !");
		System.out.println(requestedItems);
		System.out.println("======= X");
		VerifiablePresentation vp = manager.createVerifiablePresentation(toStore, verifier, requestedItems, keyPair,
				didcom, key);
		System.out.println(vp.toJson());
		System.out.println("Press enter to continue !");
		System.in.read();
		System.err
				.println("-------------------------------------------------------------------------------------------");
		System.err.println("4. [Verifier] Opening enveloped verifiable presentation !");

		VerifiablePresentation vpRec = vp.open(key);

		System.out.println(vpRec.toJson());
		System.out.println("Press enter to continue !");
		System.in.read();
		System.err
				.println("-------------------------------------------------------------------------------------------");
		System.err.println("5. [Verifier] Verifier verifying verifiable presentation !");

		if (vpRec.verifyClaimsAttributes())
			System.out.println("Successfully verified");
		else
			System.out.println("Verification failed ");
		return vp;
	}

	public void presentationDemos() throws Exception {

		System.err.println(
				"Demo A. ======================= Verifiable Microcredential Demonstration =======================");
		{
			System.out.println("Press enter to continue !");
			System.in.read();
			System.err.println(
					"-------------------------------------------------------------------------------------------");
			System.err.println("1. [Issuer] Creating Verifiable Credential with readable claims !");

			ArrayList<String> requestedItems1 = new ArrayList<String>();
			requestedItems1.add(Microcredential.holder);
			requestedItems1.add(Microcredential.label);
			requestedItems1.add(Microcredential.dataeofIssuing);
			requestedItems1.add(Microcredential.expirydate);
			String mvcClear = createMicrocredentialVC();
			System.out.println(mvcClear);
			System.out.println("Press enter to continue !");
			System.in.read();
			System.err.println(
					"-------------------------------------------------------------------------------------------");
			System.err.println("2. [Holder] Verifying Verifiable Microcredential Presentation =======================");

			if (new VerifiableCredential(mvcClear).verifyClaimsAttributes())
				System.out.println("Successfully verified Verifiable credentials !");
			else
				System.out.println("Verification failed !");
			System.out.println("Press enter to continue !");
			System.in.read();
			System.err.println(
					"-------------------------------------------------------------------------------------------");
			System.err.println("3. [Holder] Creating verifiable micropresentation !");
			System.out.println("======= Verifier requested following items !");
			System.out.println(requestedItems1);
			System.out.println("======= X");
			VerifiablePresentation vp1 = verifiablePresentation(mvcClear, requestedItems1);
			System.out.println(vp1.toJson());
			System.out.println("Press enter to continue !");
			System.in.read();
			System.err.println(
					"-------------------------------------------------------------------------------------------");
			System.err.println("4. [Verifier] Verifying verifiable micropresentation !");

			if (vp1.verifyClaimsAttributes())
				System.out.println("Successfully verified");
			else
				System.out.println("Verification failed ");

		}
		{
			System.out.println("Press enter to continue !");

			System.in.read();
			System.err.println(
					"Demo B.======================= Creating Enveloped Verifiable Microcredential =======================");
			System.err.println(
					"-------------------------------------------------------------------------------------------");
			System.err.println("1. [Issuer] Creating Enveloped Verifiable Credential with protected claims !");
			ArrayList<String> requestedItems2 = new ArrayList<String>();
			requestedItems2.add(Microcredential.holder);
			requestedItems2.add(Microcredential.label);
			requestedItems2.add(Microcredential.cycle);
			String mvcProtected = createEnvelopedMicrocredentialVC();

			VerifiablePresentation vp2 = envelopedVerifiablePresentation(mvcProtected, requestedItems2);
		}
	}
}
