package lambdaCrypto;


import java.security.SecureRandom;
import java.util.Arrays;

import struct.TwoTuple;
import util.Misc;

public  class Crypto {
	
	public enum OpMode{
		ENCRYPT, DECRYPT}
	public int blockSize = 32;
	private byte[] key;
	private byte[] iv;
	private byte[] nextIV = null;
	private CipherAlgorithm algo;
	private BlockCipherMode mode;
	private OpMode opMode;
	private boolean initialized = false;
	private byte[] buffer = new byte[32];
	private int bufferIndex = 0;
	
	
	public static void main(String[] args){
		/**
		 * |example of how crypto might be used
		 */
		int blocksize = 32;
		byte[] IV = new byte[blocksize];
		byte[] key = new byte [blocksize];
		
		byte[] plaintext = new byte[100];
		for(int i = 0; i < plaintext.length; i++){
			plaintext[i] = (byte) ((i/blocksize) +1);
		}
		
		Crypto crypto = new Crypto(OpMode.ENCRYPT);
		CipherAlgorithm eAlgo = Algorithms.getSHECipher(); // one way: use an already existing object of interface.
		BlockCipherModeEncryption eMode = (CipherAlgorithm algo, byte[] keyyy, byte[] plainText, byte[] iV) -> Modes.OFB(algo, keyyy, plainText, iV);// another way: define functional interface with static method in object declaration.
		
		crypto.init(eAlgo, eMode, IV, key);
		
		byte[] ciphertext = crypto.update(plaintext);
		byte[] pad = crypto.doFinal();
		
		System.out.println(Misc.bytesToHex(plaintext));
		System.out.println(Misc.bytesToHex(ciphertext) + Misc.bytesToHex(pad));
	}
	
	//not a thing
//	public Crypto(){
//	}
	
	public Crypto getEncryptionCrypto(){
		return new Crypto(OpMode.ENCRYPT);
	}
	
	public Crypto getDecryptionCrypto(){
		return new Crypto(OpMode.DECRYPT);
	}
	
	public Crypto(OpMode opMode){
		this.opMode = opMode;
	}
	
	/**
	 * Encrypts or decrypts data in a single-part operation, or finishes a multiple-part operation.
	 * The bytes in the input buffer, and any input bytes that may have been buffered during a previous update operation, are processed, with padding (if requested) being applied. 
	 *
	 * Upon finishing, this method resets this cipher object to the state it was in before initialized via a call to init. That is, the object is reset and needs to be re-initialized before it is available to encrypt or decrypt more data.
	 * @param input the input buffer
	 * @return the new buffer with the result
	 */
	public byte[] doFinal(){
		return doFinal(new byte[]{});
	}
	
	/**
	 * Encrypts or decrypts data in a single-part operation, or finishes a multiple-part operation.
	 * The bytes in the input buffer, and any input bytes that may have been buffered during a previous update operation, are processed, with padding (if requested) being applied. 
	 *
	 * Upon finishing, this method resets this cipher object to the state it was in before initialized via a call to init. That is, the object is reset and needs to be re-initialized before it is available to encrypt or decrypt more data.
	 * @param input the input buffer
	 * @return the new buffer with the result
	 */
	public byte[] doFinal(byte[] input){
		System.out.println(Misc.bytesToHex(buffer));
		System.out.println(bufferIndex);
		byte[] main = update(input);
		byte[] out;
		//if buffer isn't empty add a padding indicator to the end of data
		if(bufferIndex != 0){
			
			buffer[bufferIndex] = 0x69;
			bufferIndex++;
			
			TwoTuple<byte[], byte[]> result = mode.cryptBlock(algo, key, buffer, iv);
			buffer = result.getT1();
			//add buffer to end of main
			out = new byte[main.length + buffer.length];
			System.arraycopy(main, 0, out, 0, main.length);
			System.arraycopy(buffer, 0, out, main.length, buffer.length);
		}else{
			//remove padding
			int endIndex = main.length-1 ;
			while(endIndex >= 0 && (main[endIndex] == 0 || main[endIndex] == 0x69)){
				endIndex --;
				if(endIndex != 0 && main[endIndex] == 0x69){
					endIndex--;
					break;
				}
			}
			//System.out.println("endindex " + endIndex);
			out = new byte[endIndex + 1];
			System.arraycopy(main, 0, out, 0, endIndex+1);
		}

		iv = null;
		key = null;
		bufferIndex = 0;
		initialized = false;
		return out;
	}
	
	/**
	 * Initializes the cipher with key, creates a random IV to use with the cipher.
	 * @param opMode the mode of operation, encryption or decryption
	 * @param key A key to encrypt with.
	 * @return An IV that has been created for this cipher to use.
	 */
	public byte[] init(CipherAlgorithm algo, BlockCipherMode mode, byte[] key){
		byte[] iv = new byte[blockSize];
		new SecureRandom().nextBytes(iv);
		init(algo, mode, iv, key);
		return iv;
	}
	
	/**
	 * Initializes the cipher with key and IV
	 * @param opMode the mode of operation, encryption or decryption
	 * @param IV An initialization vector to use for the cipher.
	 * @param key A key to encrypt with.
	 */
	public void init(CipherAlgorithm algo, BlockCipherMode mode, byte[] IV, byte[] key){
		if(opMode == OpMode.ENCRYPT){
			if(algo instanceof DecryptionAlgorithm || mode instanceof BlockCipherModeDecryption )
				throw new RuntimeException("CipherAlgorithm and/or BlockCipher Modes are not Encryption Algorithms and/or Modes");
		}else{
			if(algo instanceof EncryptionAlgorithm || mode instanceof BlockCipherModeEncryption )
			throw new RuntimeException("CipherAlgorithm and/or BlockCipher Modes are not Decryption Algorithms and/or Modes");
		}
		this.algo = algo;
		this.mode = mode;
		this.key  = key;
		this.iv = IV;
		initialized = true;
	}
	
	
	/**
	 * Continues a multiple-part encryption or decryption operation (depending on how this cipher was initialized), processing another data part.
	 * The bytes in the input buffer are processed, and the result is stored in a new buffer.
	 *
	 * If input has a length of zero, this method returns null.
	 * @param input
	 * @return
	 */
	public byte[] update(byte[] input){
		if(!initialized)
			throw new RuntimeException("Cipher not initialized");
		byte[] iv;
		if(this.iv == null)
			iv = nextIV;
		else iv = this.iv;
		
		if(input.length == 0)
			return new byte[]{};//null;
		if(bufferIndex != 0){
			byte[] in2 = Arrays.copyOf(buffer, input.length + bufferIndex);//new byte[input.length + bufferIndex];
			//System.out.println(Misc.bytesToHex(in2));
			//System.arraycopy(buffer, 0, in2, 0, bufferIndex);
			System.arraycopy(input, 0, in2, bufferIndex, input.length);
			input = in2;
		}
		
		int numBlocks = (int) Math.floor(input.length/blockSize);
		//System.out.println(numBlocks);
		byte[] out = new byte[blockSize * numBlocks];
		for(int i = 0; i < numBlocks; i++){
			//System.out.println("i:"+i+" block:" + blockNo);
			System.arraycopy(input, blockSize*i, buffer, 0, blockSize);
			TwoTuple<byte[], byte[]> result = mode.cryptBlock(algo, key, buffer, iv);
			System.arraycopy(result.getT1(), 0, out, i * blockSize, blockSize);
			iv = result.getT2();
		}
		buffer = new byte[blockSize];
		if(input.length % blockSize == 0){
			
			bufferIndex = 0;
		}else{
			//buffer = new byte[BLOCKSIZE];
			System.arraycopy(input, numBlocks*blockSize, buffer, 0, input.length - numBlocks*blockSize);
			bufferIndex = input.length - numBlocks*blockSize;
		}
		System.out.println("buffer: " + Misc.bytesToHex(buffer));
		return out;

//		byte[] inputNew = new byte[buffer.length + input.length];
//		System.arraycopy(buffer, 0, inputNew, 0, buffer.length);
//		System.arraycopy(input, 0, inputNew, buffer.length, input.length);
//		int length = (int) Math.ceil(inputNew.length/(double) blockSize);
//		int newLength = length * blockSize; 
//		byte[] input2 = new byte[newLength];
//		input2 = Arrays.copyOf(inputNew, newLength); 
//	
//		byte[][] split = new byte[length][blockSize];
//	    int start = 0;
//	    for(int i = 0; i < split.length; i++) {
//	        split[i] = Arrays.copyOfRange(input2, start, start + blockSize); 
//	        start += blockSize ;
//	    }
//	    		
//		bufferIndex = inputNew.length % blockSize;
//		int finalArrayLength = newLength;
//		int splitTravel = split.length;
//		if (inputNew.length % blockSize != 0){
//			buffer = new byte[bufferIndex];
//			System.arraycopy(split[split.length-1], 0, buffer, 0, bufferIndex); 
//			splitTravel--;
//			finalArrayLength = (length -1) * blockSize;
//		}
//		else{
//			buffer = new byte[0];
//			bufferIndex = 0;
//		}
//
//		byte[] finalArray = new byte[finalArrayLength]; 
//		
//		int i = 0;
//		for (int j = 0; j < splitTravel; j++){
//			TwoTuple<byte[], byte[]> crypto = mode.cryptBlock(algo, key, split[j], iv); 
//			byte[] array = crypto.getT1();
//	    	System.arraycopy(array, 0, finalArray, i, blockSize);
//	    	i+=blockSize;	    	
//	   	}
//
//		return finalArray;		
	}

	/**
	 * @return the cipher algorithm
	 */
	public CipherAlgorithm getAlgorithm() {
		return algo;
	}

	/**
	 * @return the block cipher mode
	 */
	public BlockCipherMode getMode() {
		return mode;
	}
	public void setOpMode(OpMode a) {
		this.opMode = a;
	}
}

