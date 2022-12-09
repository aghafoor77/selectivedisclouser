package org.ri.se.selectivedisclosure.security;

import java.security.KeyPair;

public interface ICryptoProcessor {

	//public byte[] encrypt(byte[] key,GDSOHeader gdsoHeader, byte [] data) throws Exception;
	//public byte[] encrypt(byte key[], GenericDataSharingObject genericDataSharingObject) throws Exception;
	
	//public byte[] decrypt(byte [] key, GenericDataSharingObject genericDataSharingObject) throws Exception;
	
	public byte[] generateSymmetrickey(SecurityContext securityContext) throws Exception;
	
	public KeyPair generateRSAKeyPair(int keySize) throws Exception;
	
	//public byte[] encrypt(PublicKey publicKey, GenericDataSharingObject genericDataSharingObject) throws Exception ;

	//public byte[] decrypt(PrivateKey privateKey, GenericDataSharingObject genericDataSharingObject) throws Exception ;

	//public byte[] encrypt(PrivateKey privateKey, GenericDataSharingObject genericDataSharingObject) throws Exception ;
	
	//public byte[] decrypt(PublicKey publicKey, GenericDataSharingObject genericDataSharingObject) throws Exception ;
	
}
