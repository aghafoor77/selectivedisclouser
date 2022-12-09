package org.acreo.security.utils;

import java.io.IOException;

import org.acreo.security.exceptions.VeidblockException;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;

public class DistinguishName extends X500Name {

	private DistinguishName(String x500Name) throws IOException {
		super(x500Name);

	}

	public static DistinguishName.Builder builder() {
		return new Builder();
	}

	public static class Builder {
		X500Name dn = null;

		protected Builder() {
			// Hide default constructor
		}

		public DistinguishName.Builder name(String name) throws IOException {
			if (null == name) {
				return this;
			}
			if (dn == null) {
				dn = new X500Name("CN=" + name);
			} else {
				String updatedStr = dn.toString() + ",CN=" + name;
				dn = new X500Name(updatedStr);
			}

			return this;
		}

		public DistinguishName.Builder organization(String organization) throws IOException {
			if (null == organization) {
				return this;
			}
			if (dn == null) {
				dn = new X500Name("O=" + organization);
			} else {
				String updatedStr = dn.toString() + ",O=" + organization;
				dn = new X500Name(updatedStr);
			}

			return this;
		}

		public DistinguishName.Builder organizationUnit(String organizationUnit) throws IOException {
			if (null == organizationUnit) {
				return this;
			}
			if (dn == null) {
				dn = new X500Name("OU=" + organizationUnit);
			} else {
				String updatedStr = dn.toString() + ",OU=" + organizationUnit;
				dn = new X500Name(updatedStr);
			}

			return this;
		}

		public DistinguishName.Builder locality(String locality) throws IOException {
			if (null == locality) {
				return this;
			}
			if (dn == null) {
				dn = new X500Name("L=" + locality);
			} else {
				String updatedStr = dn.toString() + ",L=" + locality;
				dn = new X500Name(updatedStr);
			}

			return this;
		}

		public DistinguishName.Builder state(String state) throws IOException {
			if (null == state) {
				return this;
			}
			if (dn == null) {
				dn = new X500Name("ST=" + state);
			} else {
				String updatedStr = dn.toString() + ",ST=" + state;
				dn = new X500Name(updatedStr);
			}
			return this;
		}

		public DistinguishName.Builder country(String country) throws IOException {
			if (null == country) {
				return this;
			}
			if (dn == null) {
				dn = new X500Name("C=" + country);
			} else {
				String updatedStr = dn.toString() + ",C=" + country;
				dn = new X500Name(updatedStr);
			}
			return this;
		}

		public DistinguishName.Builder email(String email) throws IOException {
			if (null == email) {
				return this;
			}
			if (dn == null) {
				dn = new X500Name("EMAIL=" + email);
			} else {
				String updatedStr = dn.toString() + ",EMAIL=" + email;
				dn = new X500Name(updatedStr);
			}
			return this;
		}

		public DistinguishName.Builder url(String url) throws IOException {
			if (null == url) {
				return this;
			}
			if (dn == null) {
				dn = new X500Name(BCStyle.DC+"="+ url);
			} else {
				String updatedStr = dn.toString() + ","+BCStyle.DC+"=" + url;
				dn = new X500Name(updatedStr);
			}
			return this;
		}

		public DistinguishName build() throws VeidblockException {

			try {
				return new DistinguishName(dn.toString());
			} catch (IOException e) {
				throw new VeidblockException(e.getMessage());
			}
		}

		public DistinguishName build(String x500Name) throws VeidblockException {
			try {
				this.dn = new X500Name(x500Name);
			} catch (Exception e) {
				throw new VeidblockException(e.getMessage());
			}
			return build();
		}

		public DistinguishName build(DistinguishNameCO distinguishNameCO) throws VeidblockException {
			try {

				name(distinguishNameCO.getName());
				organization(distinguishNameCO.getOrganization());
				organizationUnit(distinguishNameCO.getOrganizationUnit());
				locality(distinguishNameCO.getLocality());
				state(distinguishNameCO.getState());
				country(distinguishNameCO.getCountry());
				email(distinguishNameCO.getEmail());
				url(distinguishNameCO.getUrl());

			} catch (IOException e) {
				throw new VeidblockException(e.getMessage());
			}
			return build();
		}
	}

	public String getId() {
		try {
			return this.getRDNs(BCStyle.CN)[0].getTypesAndValues()[0].getValue().toString();			
		} catch (Exception e) {
			return null;
		}
	}

	@Override
	public String toString() {
		return super.toString();
	}
	
	/**/
	
}