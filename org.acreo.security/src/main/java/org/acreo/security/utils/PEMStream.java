package org.acreo.security.utils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import org.acreo.security.exceptions.VeidblockException;

import sun.security.pkcs10.PKCS10;
import sun.security.provider.X509Factory;

public class PEMStream {

	private static final String CSR_START_JAVA_TAG = "-----BEGIN NEW CERTIFICATE REQUEST-----";
	private static final String CSR_END_JAVA_TAG = "-----END NEW CERTIFICATE REQUEST-----";

	private static final String CSR_START_OPENSSL_TAG = "-----BEGIN CERTIFICATE REQUEST-----";
	private static final String CSR_END_OPENSSL_TAG = "-----END CERTIFICATE REQUEST-----";

	private static final String PUB_START_JAVA_TAG = "-----BEGIN RSA PUBLIC KEY-----";
	private static final String PUB_END_JAVA_TAG = "-----END RSA PUBLIC KEY-----";

	public boolean csr2pem(byte[] encodedCSR, ByteArrayOutputStream outStream) {
		if (null == outStream || null == encodedCSR) {
			return false;
		}
		PrintStream printStream = new PrintStream(outStream);
		printStream.println(CSR_START_JAVA_TAG);
		printStream.println(Base64.getMimeEncoder().encodeToString(encodedCSR));
		printStream.println(CSR_END_JAVA_TAG);
		printStream.close();
		return true;
	}

	public boolean pem2csr(String pemCSR, ByteArrayOutputStream outStream) throws IOException {
		if (null == outStream || null == pemCSR || pemCSR.length() == 0) {
			return false;
		}
		pemCSR = pemCSR.replaceAll(CSR_START_JAVA_TAG, "").replaceAll(CSR_END_JAVA_TAG, "").trim();
		// Handle OpenSSL PKCS10 request
		pemCSR = pemCSR.replaceAll(CSR_START_OPENSSL_TAG, "").replaceAll(CSR_END_OPENSSL_TAG, "").trim();
		byte[] encodedPKCS10 = Base64.getMimeDecoder().decode(pemCSR);
		outStream.write(encodedPKCS10);
		outStream.flush();
		return true;
	}

	public PKCS10 pem2PKCS10(String pemCSR) throws VeidblockException {
		ByteArrayOutputStream outStream = new ByteArrayOutputStream();
		try {
			if (pem2csr(pemCSR, outStream)) {
				return new PKCS10(outStream.toByteArray());
			}
			return null;
		} catch (Exception exp) {
			throw new VeidblockException(exp);
		}
	}

	public byte[] pem2csr(String pemCSR) throws VeidblockException {
		ByteArrayOutputStream outStream = new ByteArrayOutputStream();
		try {
			if (pem2csr(pemCSR, outStream)) {
				return outStream.toByteArray();
			}
			return null;
		} catch (Exception exp) {
			throw new VeidblockException(exp);
		}
	}

	public boolean x509Cert2pem(X509Certificate cert, ByteArrayOutputStream byteArrayOutputStream)
			throws CertificateEncodingException {
		PrintStream out = new PrintStream(byteArrayOutputStream);
		out.println(X509Factory.BEGIN_CERT);
		out.println(Base64.getMimeEncoder().encodeToString(cert.getEncoded()));
		out.println(X509Factory.END_CERT);
		out.close();
		return true;
	}

	public boolean pem2x509Certificate(String pemX509Cert, ByteArrayOutputStream outStream)
			throws IOException, Exception {
		if (null == outStream || null == pemX509Cert || pemX509Cert.length() == 0) {
			return false;
		}
		byte[] encodedX509Cert = Base64.getMimeDecoder()
				.decode(pemX509Cert.replaceAll(X509Factory.BEGIN_CERT, "").replaceAll(X509Factory.END_CERT, ""));
		outStream.write(encodedX509Cert);
		outStream.flush();
		return true;
	}

	public X509Certificate pem2x509Cert(String pemX509Cert) throws CertificateException, IOException, Exception {
		ByteArrayOutputStream outStream = new ByteArrayOutputStream();
		if (pem2x509Certificate(pemX509Cert, outStream)) {
			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
			InputStream in = new ByteArrayInputStream(outStream.toByteArray());
			return (X509Certificate) certFactory.generateCertificate(in);
		}
		return null;
	}

	public String toPem(X509Certificate x509Certificate) {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		try {
			if (x509Cert2pem(x509Certificate, baos)) {
				String aCertPem = new String(baos.toByteArray());
				return aCertPem;
			} else {
				return null;
			}
		} catch (Exception ex) {
			ex.printStackTrace();
			return null;
		} finally {
			if (null != baos) {
				try {
					baos.close();
				} catch (IOException e) {
					return null;
				}
			}
		}
	}

	public String toBase64String(PublicKey publicKey) {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		PrintStream out = new PrintStream(baos);
		out.println(Base64.getEncoder().encodeToString(publicKey.getEncoded()));
		out.close();
		return new String(baos.toByteArray());
	}

	public PublicKey fromBase64StringToPublicKey(String publicKeyEncoded) throws VeidblockException {
		byte[] pKey = Base64.getDecoder().decode(publicKeyEncoded);
		try {
			PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(pKey));
			return publicKey;
		} catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
			throw new VeidblockException(e);
		}
	}

	public String toPem(PublicKey publicKey) {
		return PUB_START_JAVA_TAG + "\n" + toBase64String(publicKey) + PUB_END_JAVA_TAG;
	}

	public PublicKey fromPem(String publicKeyEncoded) throws VeidblockException {
		String temp = publicKeyEncoded;
		temp = temp.replace(PUB_START_JAVA_TAG, "");
		temp = temp.replace(PUB_END_JAVA_TAG, "");
		temp = temp.trim();
		return fromBase64StringToPublicKey(temp);
	}

	public String toPemCertChain(X509Certificate x509Certificate[]) {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		String allCertInPem = "";
		try {
			PEMStream pemStream = new PEMStream();
			for (X509Certificate tempX509 : x509Certificate) {
				if (pemStream.x509Cert2pem(tempX509, baos)) {
					String aCertPem = new String(baos.toByteArray());
					allCertInPem = allCertInPem + "Serical No:" + tempX509.getSerialNumber().toString() + "\n";
					allCertInPem = allCertInPem + aCertPem.toString() + "\n";
					baos = new ByteArrayOutputStream();
				} else {
					return null;
				}
			}
		} catch (Exception ex) {
			ex.printStackTrace();
			return null;
		} finally {
			if (null != baos) {
				try {
					baos.close();
				} catch (IOException e) {
					return null;
				}
			}
		}
		return allCertInPem;
	}

	public X509Certificate[] extractCertChain(String pemChain) throws Exception {
		String temp = new String(pemChain);
		boolean bool = temp.contains(X509Factory.BEGIN_CERT);
		List<X509Certificate> chain = new ArrayList<X509Certificate>();
		while (bool) {
			// Remove Serial No
			temp = temp.substring(temp.indexOf(X509Factory.BEGIN_CERT));
			String aCert = temp.substring(temp.indexOf(X509Factory.BEGIN_CERT),
					temp.indexOf(X509Factory.END_CERT) + X509Factory.END_CERT.length());
			X509Certificate certificate = pem2x509Cert(aCert);
			chain.add(certificate);
			temp = temp.substring(temp.indexOf(X509Factory.END_CERT) + X509Factory.END_CERT.length());
			bool = temp.contains(X509Factory.BEGIN_CERT);
		}
		X509Certificate x509Certificate[] = new X509Certificate[chain.size()];
		int i = 0;
		for (X509Certificate certificate : chain) {
			x509Certificate[i] = certificate;
			i++;
		}
		return x509Certificate;
	}

	public static void main(String arg[]) {

		byte[] dd = { 10, 11, 12, 13, 14 };
		System.out.println(PEMStream.bytesToHex(dd));
		System.out.println(PEMStream.hexToBytes(PEMStream.bytesToHex(dd))[4]);
	}

	private final static char[] hexArray = "0123456789ABCDEF".toCharArray();

	public static String bytesToHex(byte[] bytes) {
		char[] hexChars = new char[bytes.length * 2];
		for (int j = 0; j < bytes.length; j++) {
			int v = bytes[j] & 0xFF;
			hexChars[j * 2] = hexArray[v >>> 4];
			hexChars[j * 2 + 1] = hexArray[v & 0x0F];
		}

		return new String(hexChars);
	}

	public static byte[] hexToBytes(String s) {
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
		}
		return data;
	}

	public static String toHex(PublicKey publicKey) {
		return bytesToHex(publicKey.getEncoded());

	}

	public PublicKey fromHex(String publicKeyHexEncoded) throws VeidblockException {
		byte[] pKey = hexToBytes(publicKeyHexEncoded);
		try {
			PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(pKey));
			return publicKey;
		} catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
			throw new VeidblockException(e);
		}
	}

	public PrivateKey getPrivateKey(byte[] endPrivateKey) throws VeidblockException {
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(endPrivateKey);
		PrivateKey privKey = null;
		try {
			KeyFactory kf = KeyFactory.getInstance("RSA");
			privKey = kf.generatePrivate(keySpec);
		} catch (Exception e) {
			throw new VeidblockException(e);
		}
		return privKey;
	}
}