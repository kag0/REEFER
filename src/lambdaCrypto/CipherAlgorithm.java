package lambdaCrypto;

public interface CipherAlgorithm {
	
	/**
	 * Crypt text using this algorithm
	 * @param key
	 * @param inputtext
	 * @return the result of putting inputtext through this algorithm with given key.
	 */
	public byte[] cryptBlock(byte[] key, byte[] inputtext);
}
