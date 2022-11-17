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
import java.security.spec.X509EncodedKeySpec;

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
		Assertions.hasEnsuredPredicate(sr, "randomized");
		
		byte[] secureBytes = new byte[32];
		(new SecureRandom()).nextBytes(secureBytes);
		Assertions.hasEnsuredPredicate(secureBytes, "randomized");
		
		sr.setSeed(secureBytes);
		// all secure
		
		Assertions.hasEnsuredPredicate(sr, "randomized"); // fails
		Assertions.predicateErrors(0); // passes
		Assertions.constraintErrors(0); // passes
		Assertions.typestateErrors(0); // passes
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
	
	@Test
	public void missingErrorsWhenCallingAMethodMultipleTimes() throws Exception {
		X509EncodedKeySpec keySpec1 = new X509EncodedKeySpec("insecureKeyBytes".getBytes()); // RequiredPredicateError
		X509EncodedKeySpec keySpec2 = new X509EncodedKeySpec("insecureKeyBytes".getBytes()); // RequiredPredicateError
		
		Assertions.notHasEnsuredPredicate(keySpec1, "speccedKey");
		Assertions.notHasEnsuredPredicate(keySpec2, "speccedKey");
		
		KeyFactory kf = KeyFactory.getInstance("RSA");
		PublicKey pubkey1 = kf.generatePublic(keySpec1); // RequiredPredicateError
		Assertions.notHasEnsuredPredicate(pubkey1);
		// generating another public key is not a typestate misuse, but the additional RequiredPredicateError is not reported
		PublicKey pubkey2 = kf.generatePublic(keySpec2); // missing RequiredPredicateError
		Assertions.notHasEnsuredPredicate(pubkey2);
		
		Assertions.predicateErrors(4); // fails
	}
	
	
}
