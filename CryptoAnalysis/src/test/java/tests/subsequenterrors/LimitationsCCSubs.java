package tests.subsequenterrors;

import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;

import java.io.File;
import java.io.FileInputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import org.junit.Test;

import crypto.analysis.CryptoScannerSettings;
import crypto.analysis.CrySLRulesetSelector.Ruleset;
import test.UsagePatternTestingFramework;
import test.assertions.Assertions;

public class LimitationsCCSubs extends UsagePatternTestingFramework{
	
	// Settings
	
	@Override
	protected CryptoScannerSettings getSettings() {
		CryptoScannerSettings settings = new CryptoScannerSettings();
		settings.setSubsequentErrorDetection(true);
		return settings;
	}
	
	@Override
	protected Ruleset getRuleSet() {
		return Ruleset.JavaCryptographicArchitecture_BET;
	}

	//
	// Limitations caused by bugs in CCSast
	//
	
	public char[] generateRandomPassword() {
		SecureRandom rnd = new SecureRandom();
		char[] defaultKey = new char[20];
		for (int i = 0; i < 20; i++) {
			defaultKey[i] = (char) (rnd.nextInt(26) + 'a');
		}
		return defaultKey;
	}
	
	@Test
	public void usingNotRandomizedSaltForPBEAndEncryption() throws Exception{
		char[] password = "test".toCharArray();
		
		// Generate Randomized Iv for CBC Mode
		byte[] ivBytes = new byte[128];
		new SecureRandom().nextBytes(ivBytes);
		IvParameterSpec iv = new IvParameterSpec(ivBytes);
		
		// Generate Salt which is insecure for encryption
		byte[] salt = "notRandomizedSalt".getBytes();
		
		// Generate SecretKey from Password
		PBEKeySpec pbeKeySpec = new PBEKeySpec(password, salt, 40000, 256);
		Assertions.dependentError(0);
		
		pbeKeySpec.clearPassword();
		
		SecretKeyFactory skf = SecretKeyFactory.getInstance("PBEWithHmacSHA224AndAES_256");
		SecretKey sk = skf.generateSecret(pbeKeySpec);
		//Assertions.dependentError(1, 0); // this should be a subsequent error, but fails
		Assertions.dependentError(1);
		
		//Create and initialize cipher object
		Cipher cipher = Cipher.getInstance("PBEWithHmacSHA224AndAES_256/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, sk, iv);
		Assertions.dependentError(2, 1); // subsequent error
		
		// encrypt
		byte[] plainText = "ThisIsThePlainText".getBytes("UTF-8");
		byte[] cipherText = cipher.doFinal(plainText);
		
	}
	
	@Test
	public void usingNotRandomizedSaltForPBEDecryption() throws Exception{
		//Generate Key
		final byte[] salt = new byte[32];
		Assertions.notHasEnsuredPredicate(salt, "randomized");

		// salt is not required to be randomized when the key is not used for encryption
		final PBEKeySpec pbekeyspec = new PBEKeySpec(generateRandomPassword(), salt, 65000, 128);
		
		Assertions.hasEnsuredPredicate(pbekeyspec, "speccedKey");
		Assertions.notHasEnsuredPredicate(pbekeyspec, "randomizedSpeccedKey");

		SecretKeyFactory skf = SecretKeyFactory.getInstance("PBEWithHmacSHA512AndAES_256");
		SecretKey sk = skf.generateSecret(pbekeyspec);
		Assertions.hasEnsuredPredicate(sk, "generatedKey");
		Assertions.notHasEnsuredPredicate(sk, "randomizedGeneratedKey");
		

		byte[] ivBytes = "notRandomizedIV".getBytes();
		(new SecureRandom()).nextBytes(ivBytes);
		Assertions.hasEnsuredPredicate(ivBytes, "randomized");
		IvParameterSpec iv = new IvParameterSpec(ivBytes);

		// Create and initialize cipher object
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, sk, iv); // this causes a false positive

		// encrypt
		byte[] plainText = "ThisIsThePlainText".getBytes("UTF-8");
		byte[] cipherText = cipher.doFinal(plainText);
		
		pbekeyspec.clearPassword();
		
		// all secure
		Assertions.predicateErrors(0); // fails
		Assertions.constraintErrors(0);
		Assertions.typestateErrors(0);
	}
	
	@Test
	public void multiplePrecedingErrorsFailsBecauseOfCCSAST() throws Exception{
		SecureRandom sr = SecureRandom.getInstance("insecureAlg"); // root error
		Assertions.dependentError(0);
		
		byte[] insecureBytes = new byte[] {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
		sr.setSeed(insecureBytes); // root error
		Assertions.dependentError(1);
		
		KeyGenerator kg = KeyGenerator.getInstance("AES");
		kg.init(128, sr); // subsequent error
		Assertions.dependentError(2,1,0);
		SecretKey key = kg.generateKey();
	}
	
}
