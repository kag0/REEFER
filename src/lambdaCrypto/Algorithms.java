package lambdaCrypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Algorithms {
	
//	/**
//	 * Interface object defined as lambda function.
//	 */
//	public static final CipherAlgorithm SHEcrypt = (byte[] key, byte[] inputtext) -> {
//		MessageDigest mD = null;
//		try {
//			mD = MessageDigest.getInstance("SHA-256");
//		} catch (NoSuchAlgorithmException e) {
//			e.printStackTrace();
//		}
//		
//		key = mD.digest(key);
//		
//		if(key.length != inputtext.length)
//			throw new RuntimeException("Parameters are not same length for xor.");
//		
//		for(int i = 0; i < key.length; i++)
//			key[i] = (byte) (key[i]^inputtext[i]);
//		
//		return key;
//	};
	
	public static CipherAlgorithm getSHECipher(){
		return (byte[] key, byte[] inputtext) -> {
			MessageDigest mD = null;
			try {
				mD = MessageDigest.getInstance("SHA-256");
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
			}
			
			key = mD.digest(key);
			
			if(key.length != inputtext.length)
				throw new RuntimeException("Parameters are not same length for xor.");
			
			for(int i = 0; i < key.length; i++)
				key[i] = (byte) (key[i]^inputtext[i]);
			
			return key;
		};
	}
	
	/*
	 * Method that can be used to implement lambda function later.
	 */
	public static byte[] SHECrypt(byte[] key, byte[] inputtext){
		MessageDigest mD = null;
		try {
			mD = MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		
		key = mD.digest(key);
		
		if(key.length != inputtext.length)
			throw new RuntimeException("Parameters are not same length for xor.");
		
		for(int i = 0; i < key.length; i++)
			key[i] = (byte) (key[i]^inputtext[i]);
		
		return key;
	}
	
	/*
	 * The nullCipher method provides an "identity cipher" -- one that does not tranform the plaintext. As a consequence, the ciphertext is identical to the plaintext. All initialization methods do nothing.
	 */
	public static byte[] nullCipher(byte[] key, byte[] inputtext){
		return inputtext;
	}
	public static CipherAlgorithm getNullCipher(){
		return (byte[] key, byte[] input) -> nullCipher(key, input);
	}
	
}
