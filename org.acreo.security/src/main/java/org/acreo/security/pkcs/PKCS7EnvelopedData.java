package org.acreo.security.pkcs;

import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;

import org.acreo.security.crypto.CryptoPolicy;
import org.acreo.security.exceptions.VeidblockException;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.RecipientInfoGenerator;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientId;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OutputEncryptor;

public class PKCS7EnvelopedData {

	private CryptoPolicy cryptoPolicy;

	public PKCS7EnvelopedData(CryptoPolicy cryptoPolicy) {
		this.cryptoPolicy = cryptoPolicy;
	}

	public byte[] generateEnvelopedData(X509Certificate[] recipients, byte[] dataToEnvelop) throws VeidblockException {
		try {
			CMSEnvelopedDataGenerator edGenerator = new CMSEnvelopedDataGenerator();
			CMSTypedData envelopable = new CMSProcessableByteArray(dataToEnvelop);
			RecipientInfoGenerator recipientGenerator;
			for (X509Certificate recipient : recipients) {
				recipientGenerator = new JceKeyTransRecipientInfoGenerator(recipient);
				edGenerator.addRecipientInfoGenerator(recipientGenerator);
			}
			OutputEncryptor encryptor = new JceCMSContentEncryptorBuilder(resolvedEncAlgo()).build();
			CMSEnvelopedData pkcsPkiEnvelope = edGenerator.generate(envelopable, encryptor);
			return pkcsPkiEnvelope.getEncoded();
		} catch (Exception e) {
			throw new VeidblockException(e);
		}
	}

	// encryption certificate is used to identify the recipient associated with
	// the private key
	public byte[] openEnvelopedData(X509Certificate encryptionCert, PrivateKey privateKey, byte[] envelopedDataEncoded)
			throws VeidblockException {
		try {
			Provider bcProvider = new BouncyCastleProvider();
			CMSEnvelopedData envelopedData = new CMSEnvelopedData(envelopedDataEncoded);
			RecipientInformationStore recipients = envelopedData.getRecipientInfos();
			Collection c = recipients.getRecipients(new JceKeyTransRecipientId(encryptionCert));
			Iterator it = c.iterator();
			if (it.hasNext()) {
				RecipientInformation recipient = (RecipientInformation) it.next();
				return recipient.getContent(new JceKeyTransEnvelopedRecipient(privateKey).setProvider(bcProvider));
			} else {
				throw new VeidblockException("Invalid certificate !");
			}

		} catch (Exception exp) {
			throw new VeidblockException(exp);
		}
	}

	private ASN1ObjectIdentifier resolvedEncAlgo() throws VeidblockException {

		if (cryptoPolicy.getEncAlgorithm().equals("AES")) {
			switch (cryptoPolicy.getKeySize()) {
			case 128:
				return CMSAlgorithm.AES128_CBC;
			case 192:
				return CMSAlgorithm.AES192_CBC;
			case 256:
				return CMSAlgorithm.AES256_CBC;
			}
		}
		throw new VeidblockException("Ivalid algorithm. Not supported " + cryptoPolicy.getEncAlgorithm() + "["
				+ cryptoPolicy.getKeySize() + "]");

	}
}
