package org.ri.se.verifiablecredentials.usecases.microcredential;
/**
 * 
 * @author abdul.ghafoor@ri.se
 * to define header of data object
 */
public enum SDSubjectHeader {
	DRIVINGLICENCENO("drivingLicenceNo"), SOCIALSECURITYNUBER("socialSecuirtyNumber"), NAME("name"), DATEOFBIRTH("dateofBirth"),
	ISSUEDATE("issueDate"), EXPIRYDATE("expiryDate"), ADDRESS("address"), VEHIVLETYPE("vehicleType");

	private String value;

	SDSubjectHeader(String value) {
		this.value = value;
	}

	public String getValue() {
		return this.value;
	}
}
