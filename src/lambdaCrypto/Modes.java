package lambdaCrypto;

import struct.TwoTuple;
import util.Misc;

public class Modes {

	/**
	 * output feedback mode
	 * symmetric mode, can be used for both encryption and decryption.
	 * @param algo
	 * @param key
	 * @param inputtext
	 * @param IV
	 * @return a 2-tuple in the form (outputText, next) where next is the IV for the next block.
	 */
	public static TwoTuple<byte[], byte[]> OFB(CipherAlgorithm algo, byte[] key, byte[] inputText, byte[] IV){
		byte[] next;
		byte[] outputText;
		next = algo.cryptBlock(key, IV);
		outputText = Misc.XOR(next, inputText);
		return new TwoTuple<byte[], byte[]>(outputText, next);
	}
	
	public static BlockCipherMode getOFB(){
		return (CipherAlgorithm algo, byte[] key, byte[] inputText, byte[] IV) -> OFB(algo, key, inputText, IV);
	}
	
	public static TwoTuple<byte[], byte[]> ECB(CipherAlgorithm algo, byte[] key, byte[] inputText, byte[] IV){
		byte[] cipherText;
		cipherText = algo.cryptBlock(key, inputText);
		return new TwoTuple<byte[], byte[]>(cipherText, null);
	}
	
	public static TwoTuple<byte[], byte[]> CBCEncrypt(CipherAlgorithm algo, byte[] key, byte[] inputText, byte[] IV){
		byte[] next;
		byte[] outputText;
		byte[] bceText;
		bceText = Misc.XOR(inputText, IV);
		
		next = algo.cryptBlock(key, bceText);
		
		outputText = next;
		return new TwoTuple<byte[], byte[]>(outputText, next);
	}
	public static TwoTuple<byte[], byte[]> CBCDecrypt(CipherAlgorithm algo, byte[] key, byte[] inputText, byte[] IV){
		byte[] next;
		byte[] outputText;
		byte[] bceText;
		next = inputText;
		
		bceText = algo.cryptBlock(key, inputText);
		outputText = Misc.XOR(bceText, IV);
		
		return new TwoTuple<byte[], byte[]>(outputText, next);
	}
		
	public static BlockCipherMode getCBCEncrypt(){
		return (CipherAlgorithm algo, byte[] key, byte[] inputText, byte[] IV) -> CBCEncrypt(algo, key, inputText, IV);
	}
	
	public static BlockCipherMode getCBCDecrypt(){
		return (CipherAlgorithm algo, byte[] key, byte[] inputText, byte[] IV) -> CBCDecrypt(algo, key, inputText, IV);
	}

	//this was obviously not ready to be pushed into the main branch
//		public static TwoTuple<byte[], byte[]> CFB(CipherAlgorithm algo, byte[] key, byte[] inputText, byte[] IV){	 
//			byte[] next;
//			byte[] outputText;
//			byte[] bceText;
//			
//			bceText = algo.cryptBlock
//		}

	
}
