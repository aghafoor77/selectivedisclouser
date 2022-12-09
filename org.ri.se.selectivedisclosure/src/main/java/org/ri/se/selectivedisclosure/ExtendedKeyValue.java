package org.ri.se.selectivedisclosure;

import com.fasterxml.jackson.databind.ObjectMapper;

public class ExtendedKeyValue {

	private String salt;
	private String name;
	private String value;
		
	public String getSalt() {
		return salt;
	}
	public void setSalt(String salt) {
		this.salt = salt;
	}
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	public String getValue() {
		return value;
	}
	public void setValue(String value) {
		this.value = value;
	}
	public String serialize() throws Exception {
		return new ObjectMapper().writeValueAsString(this);
	}
	public void deserialize(String json) throws Exception {
		ExtendedKeyValue kv =new ObjectMapper().readValue(json, this.getClass());
		setName(kv.getName());
		setValue(kv.getValue());
		setSalt(kv.getSalt());
	}
}
