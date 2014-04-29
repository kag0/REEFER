package lambdaCrypto;

import java.security.CryptoPrimitive;
import java.util.Arrays;

import util.Misc;

public class Test {

	public static void main(String[] args) {
		byte[] IV = new byte[32];
		byte[] plainText = new byte[100];
		byte[] key = new byte[32];
		for(int i = 0; i < plainText.length; i++){
			plainText[i] = (byte) ((i/32) +1);
		}
		Crypto crypto = new Crypto(Crypto.OpMode.ENCRYPT);
		/*######################################################################
		#### Null Cipher #######################################################
		######################################################################*/
		
		crypto.init(Algorithms.getNullCipher(), Modes.getOFB(),IV, key);
		
		System.out.println(Misc.bytesToHex(Modes.OFB(Algorithms.getNullCipher(), key, plainText, IV).getT1()));
		
		byte[] _0_40 = crypto.update(Arrays.copyOf(plainText, 40));
		System.out.println(_0_40.length + ":" + Misc.bytesToHex(_0_40));
		
		byte[] rest = crypto.update(Arrays.copyOfRange(plainText, 40, plainText.length));
		System.out.println(rest.length + ":" + Misc.bytesToHex(rest));
		
		byte[] _final = crypto.doFinal();
		System.out.println(Misc.bytesToHex(_final));
		
		System.out.println("DECRYPT###############");
		
		crypto.init(Algorithms.getNullCipher(), Modes.getOFB(),IV, key);
	
		
		_0_40 = crypto.update(_0_40);
		System.out.println(_0_40.length + ":" + Misc.bytesToHex(_0_40));
		
		rest = crypto.update(rest);
		System.out.println(rest.length + ":" + Misc.bytesToHex(rest));
		
		_final = crypto.doFinal(_final);
		System.out.println(Misc.bytesToHex(_final));
		
		//######################################################################
		
		
		/*######################################################################
		#### SHE Cipher ########################################################
		######################################################################*/
		System.out.println("enCRYPT###############");
		crypto.init(Algorithms.getSHECipher(), Modes.getOFB(),IV, key);
				
		_0_40 = crypto.update(Arrays.copyOf(plainText, 40));
		System.out.println(_0_40.length + ":" + Misc.bytesToHex(_0_40));
		
		rest = crypto.update(Arrays.copyOfRange(plainText, 40, plainText.length));
		System.out.println(rest.length + ":" + Misc.bytesToHex(rest));
		
		_final = crypto.doFinal();
		System.out.println(Misc.bytesToHex(_final));
		System.out.println("DECRYPT###############");
		crypto = new Crypto(Crypto.OpMode.DECRYPT);
		
		crypto.init(Algorithms.getSHECipher(), Modes.getOFB(),IV, key);
		
	
		_0_40 = crypto.update(_0_40);
		System.out.println(_0_40.length + ":" + Misc.bytesToHex(_0_40));
		
		rest = crypto.update(rest);
		System.out.println(rest.length + ":" + Misc.bytesToHex(rest));
		
		_final = crypto.doFinal(_final);
		System.out.println( Misc.bytesToHex(_final));

		//######################################################################

	}

}
