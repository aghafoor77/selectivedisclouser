package org.ri.se.verifiablecredentials.usecases.microcredential;

import java.util.Date;
/**
 * 
 * @author abdul.ghafoor@ri.se
 * Object to provide data object
 */
public class SDSubject {
	private String drivingLicenceNo; // driving licence no
	private String socialSecuirtyNumber; // social security number
	private String name; // name of the holder
	private Date dateofBirth;// date of birth 
	private Date issueDate; // when this driving lince issues 
	private Date expiryDate; // when this driving  expired
	private String address; // Address of the licence holder
	private String vehicleType; // types of allowed vehicle

	public String getDrivingLicenceNo() {
		return drivingLicenceNo;
	}

	public void setDrivingLicenceNo(String drivingLicenceNo) {
		this.drivingLicenceNo = drivingLicenceNo;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public Date getDateofBirth() {
		return dateofBirth;
	}

	public void setDateofBirth(Date dateofBirth) {
		this.dateofBirth = dateofBirth;
	}

	public Date getIssueDate() {
		return issueDate;
	}

	public void setIssueDate(Date issueDate) {
		this.issueDate = issueDate;
	}

	public Date getExpiryDate() {
		return expiryDate;
	}

	public void setExpiryDate(Date expiryDate) {
		this.expiryDate = expiryDate;
	}

	public String getAddress() {
		return address;
	}

	public void setAddress(String address) {
		this.address = address;
	}

	public String getVehicleType() {
		return vehicleType;
	}

	public void setVehicleType(String vehicleType) {
		this.vehicleType = vehicleType;
	}

	public String getSocialSecuirtyNumber() {
		return socialSecuirtyNumber;
	}

	public void setSocialSecuirtyNumber(String socialSecuirtyNumber) {
		this.socialSecuirtyNumber = socialSecuirtyNumber;
	}
	
}
