/*
 * package org.ri.se.selectivedisclosure.test;
 * 
 * import java.util.ArrayList; import java.util.HashMap;
 * 
 * import org.ri.se.platform.datamodel.SecurityContext; import
 * org.ri.se.platform.engine.CryptoProcessor; import
 * org.ri.se.selectivedisclosure.RSAAsymmetricKeyPair; import
 * org.ri.se.selectivedisclosure.Utils; import org.ri.se.selectivedisclosure.VC;
 * import org.ri.se.selectivedisclosure.VerifiableCredential; import
 * org.ri.se.selectivedisclosure.VerifiableCredentialManager; import
 * org.ri.se.selectivedisclosure.VerifiablePresentation; import
 * org.ri.se.selectivedisclosure.microdemo.Microcredential;
 * 
 * public class TestSelectiveDisclouser {
 * 
 * public static void main(String[] args) throws Exception {
 * 
 * new TestSelectiveDisclouser().secureVCExchnage(); }
 * 
 * public void secureVCExchnage() throws Exception {
 * 
 * String walletDir =
 * "/home/ag/Desktop/RISE/development/traceability/org.ri.se.trace.test/src/main/resources";
 * String username0 = "abdul0"; String password0 = "1122334455";
 * 
 * HashMap<String, String> subjectData = new HashMap<String, String>();
 * 
 * String holder = "0x71aD1108403C28f3723d09D533337BC115528039"; String
 * controller = "0xC5B09bb75A2C4b6Bb0c91E9dac4d3cC3C40Fed05";
 * 
 * controller = VC.PREID + controller; holder = VC.PREID + holder;
 * 
 * subjectData.put(Microcredential.holder,holder); //identification of the
 * learner subjectData.put(Microcredential.label,"Big data");//(2) title of the
 * micro-credential
 * subjectData.put(Microcredential.issueraddress,"RISE AB, Kista");//(3)
 * country/Region of the issuer
 * subjectData.put(Microcredential.awardingBody,"RISE AB") ;//(4) awarding body
 * subjectData.put(Microcredential.dataeofIssuing,"20220722");//(5) date of
 * issuing subjectData.put(Microcredential.
 * learningOutcomes,"To userstand the basics of Big data ");//(6) learning
 * outcomes subjectData.put(Microcredential.workload,"8 hrs");//(7) notional
 * workload needed to achieve the learning outcomes (in European Credit Transfer
 * and Accumulation System, wherever possible)
 * subjectData.put(Microcredential.cycle,"1") ;//(8) level (and cycle, if
 * applicable) of the learning experience leading to the micro-credential
 * (European Qualifications Framework, Qualifications Frameworks in the European
 * Higher Education Area), if applicable
 * subjectData.put(Microcredential.typeOfAssesment,"Assignment");//(9) type of
 * assessment subjectData.put(Microcredential.participationForm,"Online");//(10)
 * form of participation in the learning activity
 * subjectData.put(Microcredential.typeOfQaulityAssurance,"not clear to me");//(
 * 11) type of quality assurance used to underpin the micro-credential
 * //Optional subjectData.put(Microcredential.expirydate,"20250721");//(12) date
 * of expiring
 * 
 * String didcom = "did:veid:Ox767389a9889b87cb8a"; System.out.println("\n");
 * System.out.
 * println("1. Creating Verifiable Credential with protected subject and sending to receiver !"
 * ); System.in.read(); CryptoProcessor cryptoProcessor = new CryptoProcessor();
 * byte[] key = cryptoProcessor.generateSymmetrickey(SecurityContext.AES128);
 * VerifiableCredentialManager credentialManager = new
 * VerifiableCredentialManager(); RSAAsymmetricKeyPair keyPair = new
 * Utils().getPrivateKey(username0, password0);
 * 
 * VerifiableCredential jsonVC = credentialManager.create(controller, keyPair,
 * subjectData, holder, didcom, key); String json = jsonVC.toJson();
 * System.out.println(json);
 * System.out.println("Done ==============================================");
 * 
 * System.out.println("\n");
 * System.out.println("2. Verifying Verifiable Credential at recipient !");
 * System.in.read(); // receiver if (!jsonVC.verifyOffline()) {
 * System.out.println("Failed to verify !"); }
 * System.out.println("Successfully verified !");
 * 
 * String toStore = new Utils().vcWithClaims(json, key);
 * System.out.println(toStore); verifiablePresentation(toStore); }
 * 
 * public void verifiablePresentation(String toStore) throws Exception {
 * 
 * System.out.println("\n");
 * System.out.println("3. Creating Verifiable Presentation !");
 * System.in.read();
 * 
 * VerifiableCredentialManager manager = new VerifiableCredentialManager();
 * ArrayList<String> requestedItems = new ArrayList<String>();
 * requestedItems.add("key5"); requestedItems.add("key2"); String walletDir =
 * "/home/ag/Desktop/RISE/development/traceability/org.ri.se.trace.test/src/main/resources";
 * String username0 = "abdul0"; String password0 = "1122334455";
 * RSAAsymmetricKeyPair keyPair = new Utils().getPrivateKey(username0,
 * password0); String verifier = "0xD80669C93d46c17ba45C89bc7A450148C81a90F7";
 * verifier = VC.PREID + verifier; VerifiablePresentation vp =
 * manager.createVerifiablePresentation(toStore, verifier, requestedItems,
 * keyPair); vp.verifyClaimsAttributes();
 * System.out.println(vp.verifyOffline()); }
 * 
 * 
 * }
 */