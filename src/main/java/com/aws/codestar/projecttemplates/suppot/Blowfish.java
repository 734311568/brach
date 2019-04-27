package com.aws.codestar.projecttemplates.suppot;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

/**
 * 河豚
 */
public class Blowfish {

	/**
	 * @param message 加密前的字串
	 * @return 加密後的字串
	 * @throws java.security.NoSuchAlgorithmException
	 * @throws javax.crypto.NoSuchPaddingException
	 * @throws java.security.InvalidKeyException
	 * @throws javax.crypto.IllegalBlockSizeException
	 * @throws javax.crypto.BadPaddingException
	 */
	public static String encrypt(String message) throws Exception {
		final String BLOWFISH = "Blowfish";

		KeyGenerator keyGenerator = KeyGenerator.getInstance(BLOWFISH);
		keyGenerator.init(128);
		Cipher cipher = Cipher.getInstance(BLOWFISH);
		cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec("CK6wjp6".getBytes(), BLOWFISH));
		StringBuilder stringBuilder = new StringBuilder();
		for (byte b : cipher.doFinal(message.getBytes())) {
			stringBuilder.append(String.format("%02x", b));
		}
		return stringBuilder.reverse().toString();
	}
}
