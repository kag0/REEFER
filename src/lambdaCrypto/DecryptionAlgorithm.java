package lambdaCrypto;

public interface DecryptionAlgorithm extends CipherAlgorithm {

	/**
	 * Decrypt text using this algorithm
	 * @param key
	 * @param ciphertext
	 * @return the result of putting plaintext through this decryption algorithm with given key.
	 */
	public byte[] cryptBlock(byte[] key, byte[] ciphertext);
	
}
