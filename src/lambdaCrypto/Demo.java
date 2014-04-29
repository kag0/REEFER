package lambdaCrypto;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.Scanner;

import lambdaCrypto.Crypto.OpMode;
import testpack.*;
import util.Misc;

public class Demo {

	public static void main(String[] args) {
		Demo tester = new Demo();
		// Get Run-Mode
		if (args.length > 0) {
			// HELP CMD
			if (args[0].equals("-help")) {
				tester.printOut("./src/testpack/help.txt");
				System.exit(0);
			} else if (args[0].equals("-about")) {
				tester.printOut("./src/testpack/about.txt");
				System.exit(0);
			} else if (args[0].equals("-d")) { // DECRYPT CMD
				tester.setMode(RunMode.DECRYPT);
				tester.Run(args);
				System.exit(0);
			} else if (args[0].equals("-e")) { // ENCRYPT CMD
				tester.setMode(RunMode.ENCRYPT);
				tester.Run(args);
				System.exit(0);
			} else {
				System.err.println("invalid argument:" + args[0]);
				System.exit(1);
			}
		}
		// RUNDEFAULT
		tester.Run(null);
	}

	public enum RunMode {
		DEFAULT(), ENCRYPT(), DECRYPT();

		private final String description;

		private RunMode() {
			this.description = "";
		}

		private RunMode(String a) {
			this.description = a;
		}

		@Override
		public String toString() {
			return description;
		}
	}

	private RunMode runmode;
	private String infile = "src/testpack/in.txt";
	private String firstoutfile = "src/testpack/first_out.txt";
	private String finaloutfile = "src/testpack/final_out.txt";
	private String cipher = "default cipher";
	// TODO
	private String blockmode = "default blockmode";
	private final int BLOCKSIZE = 32;
	private byte[] IV = new byte[BLOCKSIZE];
	private byte[] key = new byte[BLOCKSIZE];
	private byte[] plaintext = new byte[100];
	private byte[] ciphertext = new byte[100];
	private File plainFile;
	private File cipherFile;

	public Demo() {
		runmode = RunMode.DEFAULT;
	}

	private boolean setMode(RunMode mode) {
		runmode = mode;
		return false;
	}

	private void Run(String[] args) {
		try {
			if (args != null) {
				setFiles(args);
				if (runmode == RunMode.ENCRYPT) {
					writeByteArrayToFile(firstoutfile, runEncrypt());
					
				} else if (runmode == RunMode.DECRYPT) {
				
					writeByteArrayToFile(finaloutfile, runDecrypt());
				}
			} else {
				writeByteArrayToFile(firstoutfile, runEncrypt());
				writeByteArrayToFile(finaloutfile, runDecrypt());
			}
		} catch (Exception e) {
			e.printStackTrace();
			System.out.println("Major Problems in RUN. Some stuff went down");
		}
	}

	private byte[] runEncrypt() {
		plaintext = fileToByteArray(new File(infile));
		System.out.println("Plaintext: " +Misc.bytesToHex(plaintext));
		Crypto crypto = new Crypto(OpMode.ENCRYPT);

		//EncryptionAlgorithm eAlgo = (EncryptionAlgorithm) Algorithms.getSHECipher(); 
	
//		crypto.init(eAlgo, eMode, IV, key);
//		byte[] ctext = crypto.update(plaintext);
//		byte[] pad = crypto.doFinal();
//		
//		byte[] finalarray = new byte[100];
//		System.arraycopy(finalarray, 0, ctext, 0, ctext.length);
//		System.arraycopy(finalarray, 0, pad, 0, pad.length);
		
		crypto.init(Algorithms.getSHECipher(), Modes.getOFB(),IV, key);
		byte[] ctext = crypto.update(Arrays.copyOf(plaintext, plaintext.length));
		byte[] _final = crypto.doFinal();
		return _final;
	}

	private byte[] runDecrypt() {
		ciphertext = fileToByteArray(new File(firstoutfile));
		System.out.println("Ciphertext: " +Misc.bytesToHex(ciphertext));
		Crypto crypto = new Crypto(OpMode.DECRYPT);
		
//		CipherAlgorithm eAlgo = Algorithms.getSHECipher();
//		BlockCipherModeEncryption eMode = (CipherAlgorithm algo, byte[] keyyy,
//				byte[] plainText, byte[] iV) -> Modes.OFB(algo, keyyy,
//				plainText, iV);
//		crypto.init(eAlgo, eMode, IV, key);
//		byte[] ptext = crypto.update(ciphertext);
//		byte[] pad = crypto.doFinal();
//		
//		byte[] finalarray = new byte[100];
//		System.arraycopy(finalarray, 0, ptext, 0, ptext.length);
//		System.arraycopy(finalarray, 0, pad, 0, pad.length);
		
		crypto.init(Algorithms.getSHECipher(), Modes.getOFB(),IV, key);
		byte[] ctext = crypto.update(Arrays.copyOf(ciphertext, ciphertext.length));
		byte[] _final = crypto.doFinal();
		return _final;
	}

	private void setFiles(String[] args) {
		//TODO
		if (args[0] != "-x") {
			if (args.length == 4) {
				cipher = args[1];
				blockmode = args[2];
				infile = args[3];
				firstoutfile = args[4];
				finaloutfile = args[4] + "_final";
			} else if (args.length == 4) {
				cipher = args[1];
				blockmode = args[2];
				infile = args[3];
			} else if (args.length == 3) {
				cipher = args[1];
				blockmode = args[2];
			} else if (args.length == 2) {
				cipher = args[1];
			}
		} else {
			if (args.length == 4) {
				infile = args[2];
				firstoutfile = args[3] + ".txt";
				finaloutfile = args[3] + "_final.txt";
			} else if (args.length == 3) {
				infile = args[2];
			}
		}
	}

	private void printOut(String filename) {
		File file = new File(filename);
		try {
			Scanner in = new Scanner(file);
			while (in.hasNextLine()) {
				System.out.println(in.nextLine());
			}
			in.close();
		} catch (FileNotFoundException e) {
			System.out.println("Failure to open file to be displayed");
			e.printStackTrace();
		}
	}

	private byte[] fileToByteArray(File file) {
		try {
			return Files.readAllBytes(file.toPath());
		} catch (IOException e) {
			e.printStackTrace();
			System.out.println("Error with file in!! ahhhhhh!!");
		}
		return null;
	}

	private void writeByteArrayToFile(String filename, byte[] text) {
		BufferedOutputStream bos = null;
		try {
			System.out.println("printing...");
			FileOutputStream fos = new FileOutputStream(new File(filename));

			bos = new BufferedOutputStream(fos);
			
			
			bos.write(text);
			bos.close();
		} catch (Exception e) {
			e.printStackTrace();
			System.out.println("Write out didnt work!");
		}

	}
}
