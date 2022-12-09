package org.acreo.security.utils;

import java.math.BigInteger;
import java.util.Random;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class SGen {
	private static final char[] symbols;
	private final Random random = new Random();
	
	static {
		StringBuilder tmp = new StringBuilder();
		tmp.append('*');

		for (char ch = 'A'; ch <= 'Z'; ++ch)
			tmp.append(ch);
		tmp.append('~');
		tmp.append('-');
		for (char ch = '0'; ch <= '9'; ++ch)
			tmp.append(ch);
		tmp.append(';');
		for (char ch = 'a'; ch <= 'z'; ++ch)
			tmp.append(ch);
		tmp.append('_');
		symbols = tmp.toString().toCharArray();
	}
	public String pdc(int length) {
		
		String sampl = "1";
		for(int i=0; i < length; i++){
			sampl = sampl +"0";
		}
		BigInteger v = new BigInteger(sampl);
		long dpc = (long) (Math.random() * v.longValue());
		return ""+dpc;
	}
	
	
	public String nextString(int length) {
		char[] buf = new char[length];
		for (int idx = 0; idx < buf.length; ++idx)
			buf[idx] = symbols[random.nextInt(symbols.length)];
		return new String(buf);
	}

	public String nextHexString(int length) {
		char[] buf = new char[length];
		for (int idx = 0; idx < buf.length; ++idx)
			buf[idx] = symbols[random.nextInt(symbols.length)];
		return bytesToHex(new String(buf).getBytes());
	}
	public byte[] genReandomNo(int size, String algo) {
		try
		{
			KeyGenerator keyGen = KeyGenerator.getInstance(algo);
			keyGen.init(size); // for example
			SecretKey secretKey = keyGen.generateKey();
			return secretKey.getEncoded();
		}
		catch(Exception exp){
			return null;
		}
	}
	public long generateId() {
		BigInteger v = new BigInteger("1000000000000");
		return (long) (Math.random() * v.longValue());
	}
	
	final protected static char[] hexArray = "0123456789abcdef".toCharArray();
	public String bytesToHex(byte[] bytes) {
		char[] hexChars = new char[bytes.length * 2];
		for (int j = 0; j < bytes.length; j++) {
			int v = bytes[j] & 0xFF;
			hexChars[j * 2] = hexArray[v >>> 4];
			hexChars[j * 2 + 1] = hexArray[v & 0x0F];
		}
		return new String(hexChars);
	}
	
	public byte[] concat(byte[] a, byte[] b) {
		int aLen = a.length;
		int bLen = b.length;
		byte[] c = new byte[aLen + bLen];
		System.arraycopy(a, 0, c, 0, aLen);
		System.arraycopy(b, 0, c, aLen, bLen);
		return c;
	}
}
