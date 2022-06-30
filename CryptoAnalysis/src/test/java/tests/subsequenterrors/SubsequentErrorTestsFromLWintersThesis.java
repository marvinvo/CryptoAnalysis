package tests.subsequenterrors;

import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
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
import javax.crypto.spec.IvParameterSpec;

import org.junit.Test;

import crypto.analysis.CryptoScannerSettings;
import crypto.analysis.CrySLRulesetSelector.Ruleset;
import test.UsagePatternTestingFramework;
import test.assertions.Assertions;

public class SubsequentErrorTestsFromLWintersThesis extends UsagePatternTestingFramework{
	
	@Override
	protected CryptoScannerSettings getSettings() {
		CryptoScannerSettings settings = new CryptoScannerSettings();
		settings.setSubsequentErrorDetection(true);
		return settings;
	}

	@Test
	public void constraintErrorTest() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException{
			// Check for subsequent and root errors
			KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
			Assertions.createsARootError();
			
			SecretKey key = keyGenerator.generateKey();
			Assertions.createsASubsequentError();

			Cipher cipher = Cipher.getInstance("DES");
			Assertions.createsARootError();
			
			cipher.init(Cipher.ENCRYPT_MODE, key);
			Assertions.createsASubsequentError();

			byte[] plainText = "ThisIsThePlainText".getBytes("UTF-8");
			byte[] cipherText = cipher.doFinal(plainText);
			
			
			// double check if matches errors counts
			Assertions.constraintErrors(2);
			Assertions.predicateErrors(2);
	}
	
	/**
	 * This code contains a misuse example CogniCrypt_SAST of a Signature object.
	 * CogniCrypt_SAST reports that the object is destroyed in an non-accepting state, or in other words the object is not used to fulfill a task.
	 *
	 */
	@Test
	public void incompleteOperationErrorExample() throws NoSuchAlgorithmException, NoSuchPaddingException, GeneralSecurityException {
		Signature instance = Signature.getInstance("SHA256withRSA");
		instance.initSign(IncompleteOperationErrorExample.getPrivateKey());
		Assertions.createsASubsequentError();
		instance.update("test".getBytes());
		/**
		 * The following call is missing, therefore the Signature object is never actually used to compute a Signature.
		 */
		instance.sign();

		IncompleteOperationErrorExample ex = new IncompleteOperationErrorExample();
		ex.doInit();
		ex.doUpate();
		ex.doSign();
	}
	
	public static class IncompleteOperationErrorExample {

		private Signature signature;

		private void doInit() throws GeneralSecurityException {
			signature = Signature.getInstance("SHA256withRSA");
			signature.initSign(getPrivateKey());
			Assertions.createsASubsequentError();
			
		}

		private void doUpate() throws GeneralSecurityException {
			signature.update("test".getBytes());
		}

		private void doSign() throws SignatureException {
			/**
			 * The following call is missing, therefore the Signature object is never actually used to compute a Signature.
			 */
			signature.sign();
		}

		private static PrivateKey getPrivateKey() throws GeneralSecurityException {
			KeyPairGenerator kpgen = KeyPairGenerator.getInstance("RSA");
			kpgen.initialize(1028);
			Assertions.createsARootError();
			KeyPair gp = kpgen.generateKeyPair();
			return gp.getPrivate();
		}
	}

	@Test
	public void insecureAlg() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
		//Generate Key
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		SecureRandom secureRandom = new SecureRandom();
		int keyBitSize = 128;
		keyGenerator.init(keyBitSize, secureRandom);
		SecretKey secretKey = keyGenerator.generateKey();


		//Create and initialize cipher object
		Cipher cipher = Cipher.getInstance("AES");
		Assertions.createsARootError();
		cipher.init(Cipher.ENCRYPT_MODE, secretKey);

		// encrypt
		byte[] plainText = "ThisIsThePlainText".getBytes("UTF-8");
		byte[] cipherText = cipher.doFinal(plainText);
	}
	
	@Test
	public void insecureIVExample() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException{
		//Generate Key
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		SecureRandom secureRandom = new SecureRandom();
		int keyBitSize = 128;
		keyGenerator.init(keyBitSize, secureRandom);
		SecretKey secretKey = keyGenerator.generateKey();

		//Generate IV Bytes insecurely
		byte[] ivBytes = new byte[]{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};

		//This would be a secure way:###########################
		//byte[] ivBytes = new byte[16];
		//new SecureRandom().nextBytes(ivBytes);
		//######################################################

		IvParameterSpec iv = new IvParameterSpec(ivBytes);
		Assertions.createsARootError();

		//Create and initialize cipher object
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
		Assertions.createsASubsequentError();

		// encrypt
		byte[] plainText = "ThisIsThePlainText".getBytes("UTF-8");
		byte[] cipherText = cipher.doFinal(plainText);
	}
	
	@Test
	public void insecureIVMultipleMethods() throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, NoSuchPaddingException, InvalidAlgorithmParameterException, BadPaddingException{		
		InsecureIVMultipleMethods test = new InsecureIVMultipleMethods();

		//Create and initialize cipher object
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, test.generateKey(), test.generateIV());
		Assertions.createsASubsequentError();

		// encrypt
		byte[] plainText = "ThisIsThePlainText".getBytes("UTF-8");
		byte[] cipherText = cipher.doFinal(plainText);
	}
	
	public class InsecureIVMultipleMethods{
		public SecretKey generateKey() throws NoSuchAlgorithmException{
			//Generate Key
			KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
			SecureRandom secureRandom = new SecureRandom();
			int keyBitSize = 128;
			keyGenerator.init(keyBitSize, secureRandom);
			return keyGenerator.generateKey();
		}
		
		public IvParameterSpec generateIV(){
			byte[] ivBytes = new byte[]{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
			IvParameterSpec spec = new IvParameterSpec(ivBytes);
			Assertions.createsARootError();
			return spec;
		}
	}
	
	@Test
	public void keyGeneration() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException {
		//javax.security.spec
		BigInteger modulus = new BigInteger("123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789123456789");
		BigInteger privateExponent = new BigInteger("98765432198765432198765432198765432198765432112345678912345678912345678912345678912345678912345678912345678912345678912345678912345678912345678912345678912345678912345678912345678912345678912345678912345678912345678912");
		BigInteger publicExponent = new BigInteger("14725836914725836914725836914725836914725836912345678912345678912345678912345678912345678912345678912345678912345678912345678912345678912345678912345678912345678912345678912345678912345678912345678912345678912345678912");

		RSAPrivateKeySpec privateSpec = new RSAPrivateKeySpec(modulus, privateExponent);
		RSAPublicKeySpec publicSpec = new RSAPublicKeySpec(modulus, publicExponent);
		
		// TODO: shouldn't be more errors here?

		//java.security.KeyFactory
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PrivateKey privateKey = keyFactory.generatePrivate(privateSpec);
		PublicKey publicKey = keyFactory.generatePublic(publicSpec);
		
		//java.security.KeyPair
		KeyPair keyPair = new KeyPair(publicKey, privateKey);

		//javax.crypto.Cipher
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPrivate());
		Assertions.createsARootError();
		

		byte[] plainText = "ThisIsThePlainText".getBytes("UTF-8");
		byte[] cipherText = cipher.doFinal(plainText);
	}
	
	@Test
	public void keyPair() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		// Generate a KeyPair
		KeyPairGenerator kpgen = KeyPairGenerator.getInstance("RSA");
		kpgen.initialize(1028);
		java.security.KeyPair kp = kpgen.generateKeyPair();

		// and get the PrivateKey
		PrivateKey pk = kp.getPrivate();

		// Generate a Signature and use the private Key to sign bytes
		Signature instance = Signature.getInstance("SHA256withRSA");
		instance.initSign(pk);
		instance.update("test".getBytes());
		instance.sign();
	}
	
	@Test
	public void predicateMissingExample() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		KeyGenerator keygen = KeyGenerator.getInstance("AES");
		
		//CogniCryt_SAST reports an error in the next line saying that the key size is chosen inappropriately. 
		keygen.init(46);
		Assertions.createsARootError();
		SecretKey key = keygen.generateKey();
		
		Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
		
		//CogniCryt_SAST reports an error in the next line as the key flowing to this Cipher usage was not generated securely. 
		c.init(Cipher.ENCRYPT_MODE, key);
		Assertions.createsASubsequentError();
		byte[] encText = c.doFinal("".getBytes());
	}
	
	@Test
	public void random() throws NoSuchAlgorithmException {
		byte[] seed = new byte[]{1,3,3,7};
		SecureRandom secureRandom = new SecureRandom(seed);
		Assertions.createsARootError();
		//SecureRandom secureRandom = new SecureRandom();
		
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(secureRandom);
		Assertions.createsASubsequentError();
		
		
		SecretKey key = keyGen.generateKey();
	}
	
	@Test
	public void secureIV() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
		//Generate Key
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		SecureRandom secureRandom = new SecureRandom();
		int keyBitSize = 128;
		keyGenerator.init(keyBitSize, secureRandom);
		SecretKey secretKey = keyGenerator.generateKey();

		byte[] ivBytes = new byte[16];
		new SecureRandom().nextBytes(ivBytes);

		IvParameterSpec iv = new IvParameterSpec(ivBytes);

		//Create and initialize cipher object
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);

		// encrypt
		byte[] plainText = "ThisIsThePlainText".getBytes("UTF-8");
		byte[] cipherText = cipher.doFinal(plainText);
		
		Assertions.predicateErrors(0);
		Assertions.constraintErrors(0);
		Assertions.typestateErrors(0);
	}
	
	@Test
	public void insecureIVMultipleClasses() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
		KeyProvider keyProvider = new KeyProvider();
		IVProvider ivProvider = new IVProvider();
		
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, keyProvider.generateKey(), ivProvider.generateIV());
		Assertions.createsASubsequentError();
		
		//encrypt
		byte[] plainText = "ThisIsThePlainText".getBytes("UTF-8");
		byte[] cipherText = cipher.doFinal(plainText);
	}
	
	public class KeyProvider{
		public SecretKey generateKey() throws NoSuchAlgorithmException{
			KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
			SecureRandom secureRandom = new SecureRandom();
			int keyBitSize = 128;
			keyGenerator.init(keyBitSize, secureRandom);
			return keyGenerator.generateKey();
		}
	}
	
	public class IVProvider{
		public IvParameterSpec generateIV() {
			byte[] ivBytes = new byte[]{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
			IvParameterSpec spec = new IvParameterSpec(ivBytes);
			Assertions.createsARootError();
			return spec;
		}
	}
	
	@Override
	protected Ruleset getRuleSet() {
		return Ruleset.JavaCryptographicArchitecture;
	}
}
