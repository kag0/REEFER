package lambdaCrypto;

import struct.TwoTuple;

public interface BlockCipherMode {
	/**
	 * Encrypt or decrypt a block using this block cipher mode.
	 * @param key
	 * @param innputtext
	 * @param IV
	 * @return a 2-tuple in the form (outputtext, next) where next is the IV for the next block.
	 */
	public abstract TwoTuple<byte[], byte[]> cryptBlock(CipherAlgorithm algo, byte[] key, byte[] inputtext, byte[] IV);
	
}
