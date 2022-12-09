package org.acreo.security.certificate;

import java.io.File;

public class CertificateSuite {
	
	private String algorithm = "RSA";
	private String signatureAlgorithm = "SHA256WithRSA";//"SHA1WithRSA";
	private int keySize = 2048;
	private int certLifeInYears = 1;
	private String storeType = "jks"; //PKCS12
	private int caLifeInYears = 1;
	private String certInitCode = "43";
	private String storePath= "cert.db";
	private String privateKeyStorePath= "pk.db";
	
	public CertificateSuite(String storeName, int lifeOfCACertInYear){
		String homeDir = System.getProperty("user.home");
		File dir = new File(homeDir + File.separator + "veidblock_RT"+File.separator + "credentials"+File.separator +storeName);
		if (!dir.exists())
			dir.mkdirs();
		storeName = dir.getAbsolutePath()+File.separator+storeName; 
		setCaLifeInYears(lifeOfCACertInYear);
		setStorePath(storeName+"cert.db");
		setPrivateKeyStorePath(storeName+"pk.db");
	}
	
	public CertificateSuite (String storePathWithName){
		setStorePath(storePathWithName);
	}
	public String getAlgorithm() {
		return algorithm;
	}
	public void setAlgorithm(String algorithm) {
		this.algorithm = algorithm;
	}
	public String getSignatureAlgorithm() {
		return signatureAlgorithm;
	}
	public void setSignatureAlgorithm(String signatureAlgorithm) {
		this.signatureAlgorithm = signatureAlgorithm;
	}
	public int getKeySize() {
		return keySize;
	}
	public void setKeySize(int keySize) {
		this.keySize = keySize;
	}
	
	public int getCertLifeInYears() {
		return certLifeInYears;
	}

	public void setCertLifeInYears(int certLifeInYears) {
		this.certLifeInYears = certLifeInYears;
	}

	public String getStorePath() {
		return storePath;
	}
	public void setStorePath(String storePath) {
		this.storePath = storePath;
	}
	public String getStoreType() {
		return storeType;
	}
	public void setStoreType(String storeType) {
		this.storeType = storeType;
	}
	public int getCaLifeInYears() {
		return caLifeInYears;
	}
	public void setCaLifeInYears(int caLifeInYears) {
		this.caLifeInYears = caLifeInYears;
	}
	public String getCertInitCode() {
		return certInitCode;
	}
	public void setCertInitCode(String certInitCode) {
		this.certInitCode = certInitCode;
	}

	public String getPrivateKeyStorePath() {
		return privateKeyStorePath;
	}

	public void setPrivateKeyStorePath(String privateKeyStorePath) {
		this.privateKeyStorePath = privateKeyStorePath;
	}
}
