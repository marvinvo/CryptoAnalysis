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
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Test;

import crypto.analysis.CryptoScannerSettings;
import crypto.analysis.CrySLRulesetSelector.Ruleset;
import test.UsagePatternTestingFramework;
import test.assertions.Assertions;

public class LimitationsCCSast extends UsagePatternTestingFramework{
	
	// Settings
	
	@Override
	protected CryptoScannerSettings getSettings() {
		CryptoScannerSettings settings = new CryptoScannerSettings();
		settings.setSubsequentErrorDetection(false);
		return settings;
	}
	
	@Override
	protected Ruleset getRuleSet() {
		return Ruleset.JavaCryptographicArchitecture;
	}
	
	//
	// BUG IN CCSAST
	//
	
	@Test
	public void predicateHandlerNotPropagatePredicateOnThis() throws Exception{
		SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
		byte[] secureBytes = new byte[32];
		(new SecureRandom()).nextBytes(secureBytes);
		sr.setSeed(secureBytes);
		KeyGenerator kg = KeyGenerator.getInstance("AES");
		kg.init(128, sr);
		SecretKey key = kg.generateKey();
		// all secure
		Assertions.predicateErrors(0); // fails
	}
	
	@Test
	public void detroySecretKey() throws Exception{
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		SecretKey secretKey = keyGenerator.generateKey();
		secretKey.destroy(); 
		// secretKey should not ensure a predicate anymore
		
		// generate secure iv
		byte[] ivBytes = new byte[16];
		new SecureRandom().nextBytes(ivBytes);
		IvParameterSpec iv = new IvParameterSpec(ivBytes);
		//Create and initialize cipher object
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		
		
		// although secretKey should have negated the predicate, 
		// CCsast does not report an error here.
		// This cannot be testet with the JUnit tests, as they use 
		// a different method to validate whether a predicate is ensured or not.
		// Please analyze this method e.g. with the command line tool of CCsast.
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);

		
		// encrypt
		byte[] plainText = "ThisIsThePlainText".getBytes("UTF-8");
		byte[] cipherText = cipher.doFinal(plainText);
	}
	

	@Test
	public void usingNotRandomizedSaltForPBEAndEncryption() throws Exception{
		char[] password = "test".toCharArray();
		
		// Generate Randomized Salt
		byte[] salt = new byte[128];
		new SecureRandom().nextBytes(salt);
		
		// all secure till here
		
		
		// Generate SecretKey from Password
		PBEKeySpec pbeKeySpec = new PBEKeySpec(password, salt, 40000, 256); // error for hardcoded password
		Assertions.predicateErrors(1); // passes
		Assertions.notHasEnsuredPredicate(pbeKeySpec, "speccedKey");
		

		SecretKeyFactory skf = SecretKeyFactory.getInstance("PBEWithHmacSHA224AndAES_256");
		SecretKey sk = skf.generateSecret(pbeKeySpec); // but no error for using insecure PBEKeySpec
		
		
		// Assertions.predicateErrors(1); // passes but should not
		Assertions.predicateErrors(2); // fails
		
		pbeKeySpec.clearPassword();
	}
	
	@Test
	public void cipherNotRetrieveGeneratedKeyPredicate() throws Exception {
		RSAKeyGenParameterSpec parameters = new RSAKeyGenParameterSpec(4096, BigInteger.valueOf(65537));
		Assertions.hasEnsuredPredicate(parameters, "preparedRSA");
		
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(parameters);
		KeyPair keyPair = generator.generateKeyPair();
		Assertions.hasEnsuredPredicate(keyPair, "generatedKeypair");
		
		PublicKey pub = keyPair.getPublic();
		Assertions.hasEnsuredPredicate(pub, "generatedPubkey");
		Assertions.hasEnsuredPredicate(pub, "generatedKey");
		
		Cipher c = Cipher.getInstance("RSA");
		c.init(Cipher.DECRYPT_MODE, pub);

		byte[] plainText = "ThisIsThePlainText".getBytes("UTF-8");
		byte[] cipherText = c.doFinal(plainText);
		
		Assertions.predicateErrors(0); // fails
	
	}
	
	@Test
	public void cipherNotRetrieveGeneratedKeyPredicate2() throws GeneralSecurityException {
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		generator.initialize(4096);
		KeyPair keyPair = generator.generateKeyPair();
		Assertions.hasEnsuredPredicate(keyPair, "generatedKeypair");
		
		Cipher c = Cipher.getInstance("RSA");
		c.init(Cipher.DECRYPT_MODE, keyPair.getPublic());
		Assertions.predicateErrors(1); // fails

	}
	
	
}
