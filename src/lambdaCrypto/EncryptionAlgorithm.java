package lambdaCrypto;

public interface EncryptionAlgorithm extends CipherAlgorithm {

	/**
	 * Encrypt text using this algorithm
	 * @param key
	 * @param plaintext
	 * @return the result of putting ciphertext through this encryption algorithm with given key.
	 */
	public byte[] cryptBlock(byte[] key, byte[] plaintext);
}
