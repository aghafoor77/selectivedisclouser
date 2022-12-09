package org.acreo.security.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;

import org.acreo.security.exceptions.VeidblockException;

public class CryptoIO {
	public boolean writeData(String id2, String json) {
		try {
			FileWriter file = new FileWriter(id2);
			file.write(json);
			file.flush();
			file.close();
			return true;
		} catch (IOException exp) {
			return false;
		}
	}

	public byte[] readData(String id2) throws VeidblockException{
		try {
			File file = new File(id2);
			FileInputStream fis = new FileInputStream(file);
			byte[] data = new byte[(int) file.length()];
			fis.read(data);
			fis.close();
			if(data == null || data.length ==0){
				throw new VeidblockException("Problems when reading shared secret file !");
			}
			return data;
		} catch (IOException exp) {
			throw new VeidblockException(exp);
		}
	}
	
	public static void traceMe(String message){
		System.out.println("---> "+message);
	}
}
