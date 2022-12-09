package org.ri.se.verifiablecredentials.entities;

public enum JSONLDSignatureType {
	Ed25519Signature2018("Ed25519Signature2018"),
	Ed25519Signature2020("Ed25519Signature2020"),
	EcdsaSecp256k1Signature2019("EcdsaSecp256k1Signature2019"),
	RsaSignature2018("RsaSignature2018"),
	JsonWebSignature2020("JsonWebSignature2020"),
	JcsEd25519Signature2020("JcsEd25519Signature2020"),
	JcsEcdsaSecp256k1Signature2019("JcsEcdsaSecp256k1Signature2019");
	 
    private String scheme;
 
    public String getScheme(){
        return this.scheme;
    }
 
    // enum constructor - can not be public or protected
    JSONLDSignatureType(String scheme){
        this.scheme = scheme;
    }
}
