package tests.subsequenterrors;

import java.io.File;
import java.io.FileInputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.Signature;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import org.junit.Test;

import crypto.analysis.CrySLRulesetSelector.Ruleset;
import crypto.analysis.CryptoScannerSettings;
import test.UsagePatternTestingFramework;
import test.assertions.Assertions;

public class ImprovementsCCSubs extends UsagePatternTestingFramework{
	
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
	// Predicate Ensuring Constraint Condition Tests
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
	public void predicateEnsuringConstraintsConditionTest1() throws Exception{
		final byte[] salt = new byte[32];
		Assertions.notHasEnsuredPredicate(salt, "randomized");

		// salt is not required to be randomized when the key is not used for encryption
		final PBEKeySpec pbekeyspec = new PBEKeySpec(generateRandomPassword(), salt, 65000, 128);
		Assertions.predicateErrors(0);
		Assertions.hasEnsuredPredicate(pbekeyspec, "speccedKey");
		Assertions.notHasEnsuredPredicate(pbekeyspec, "randomizedSpeccedKey");

		pbekeyspec.clearPassword();
	}
	
	@Test
	public void predicateEnsuringConstraintsConditionTest2() throws Exception{
		final byte[] salt = new byte[32];
		(new SecureRandom()).nextBytes(salt);
		Assertions.hasEnsuredPredicate(salt, "randomized");

		// salt is not required to be randomized when the key is not used for encryption
		final PBEKeySpec pbekeyspec = new PBEKeySpec(generateRandomPassword(), salt, 65000, 128);
		Assertions.predicateErrors(0);
		Assertions.hasEnsuredPredicate(pbekeyspec, "speccedKey");
		Assertions.hasEnsuredPredicate(pbekeyspec, "randomizedSpeccedKey");

		pbekeyspec.clearPassword();
	}
	
	@Test
	public void predicateEnsuringConstraintsConditionTest3() throws Exception{
		final byte[] iv = new byte[32];
		(new SecureRandom()).nextBytes(iv);
		Assertions.hasEnsuredPredicate(iv, "randomized");
		
		IvParameterSpec ivSpec = new IvParameterSpec(iv);
		Assertions.hasEnsuredPredicate(ivSpec, "preparedIV");
		Assertions.hasEnsuredPredicate(ivSpec, "randomizedPreparedIV");
	}
	
	@Test
	public void predicateEnsuringConstraintsConditionTest4() throws Exception{
		final byte[] iv = new byte[32];
		Assertions.notHasEnsuredPredicate(iv, "randomized");
		
		IvParameterSpec ivSpec = new IvParameterSpec(iv);
		Assertions.hasEnsuredPredicate(ivSpec, "preparedIV");
		Assertions.notHasEnsuredPredicate(ivSpec, "randomizedPreparedIV");
	}
	
	@Test
	public void predicateEnsuringConstraintsConditionTest5() throws Exception{
		final byte[] iv = new byte[128];
		(new SecureRandom()).nextBytes(iv);
		Assertions.hasEnsuredPredicate(iv, "randomized");
		
		GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
		Assertions.hasEnsuredPredicate(gcmSpec, "preparedGCM");
		Assertions.hasEnsuredPredicate(gcmSpec, "randomizedPreparedGCM");
	}
	
	@Test
	public void predicateEnsuringConstraintsConditionTest6() throws Exception{
		final byte[] iv = new byte[128];
		Assertions.notHasEnsuredPredicate(iv, "randomized");
		
		GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
		Assertions.hasEnsuredPredicate(gcmSpec, "preparedGCM");
		Assertions.notHasEnsuredPredicate(gcmSpec, "randomizedPreparedGCM");
	}
	
	@Test
	public void predicateEnsuringConstraintsConditionTest7() throws Exception{
		final byte[] salt = new byte[32];
		Assertions.notHasEnsuredPredicate(salt, "randomized");

		PBEParameterSpec pbeSpec = new PBEParameterSpec(salt, 10000);
		Assertions.hasEnsuredPredicate(pbeSpec, "preparedPBE");
		Assertions.notHasEnsuredPredicate(pbeSpec, "randomizedPreparedPBE");
	}
	
	@Test
	public void predicateEnsuringConstraintsConditionTest8() throws Exception{
		final byte[] salt = new byte[32];
		(new SecureRandom()).nextBytes(salt);
		Assertions.hasEnsuredPredicate(salt, "randomized");

		PBEParameterSpec pbeSpec = new PBEParameterSpec(salt, 10000);
		Assertions.hasEnsuredPredicate(pbeSpec, "preparedPBE");
		Assertions.hasEnsuredPredicate(pbeSpec, "randomizedPreparedPBE");
	}
	
	@Test
	public void predicateEnsuringConstraintsConditionTest9() throws Exception{
		final byte[] salt = new byte[32];
		Assertions.notHasEnsuredPredicate(salt, "randomized");

		// salt is not required to be randomized when the key is not used for encryption
		final PBEKeySpec pbekeyspec = new PBEKeySpec(generateRandomPassword(), salt, 65000, 128);
		
		Assertions.predicateErrors(0);
		Assertions.hasEnsuredPredicate(pbekeyspec, "speccedKey");
		Assertions.notHasEnsuredPredicate(pbekeyspec, "randomizedSpeccedKey");

		SecretKeyFactory skf = SecretKeyFactory.getInstance("PBEWithHmacSHA512AndAES_256");
		SecretKey sk = skf.generateSecret(pbekeyspec);
		Assertions.hasEnsuredPredicate(sk, "generatedKey");
		Assertions.notHasEnsuredPredicate(sk, "randomizedGeneratedKey");
		
		pbekeyspec.clearPassword();
		
	}
	
	@Test
	public void predicateEnsuringConstraintsConditionTest10() throws Exception{
		final byte[] salt = new byte[32];
		(new SecureRandom()).nextBytes(salt);
		Assertions.hasEnsuredPredicate(salt, "randomized");

		// salt is not required to be randomized when the key is not used for encryption
		final PBEKeySpec pbekeyspec = new PBEKeySpec(generateRandomPassword(), salt, 65000, 128);
		
		Assertions.predicateErrors(0);
		Assertions.hasEnsuredPredicate(pbekeyspec, "speccedKey");
		Assertions.hasEnsuredPredicate(pbekeyspec, "randomizedSpeccedKey");

		SecretKeyFactory skf = SecretKeyFactory.getInstance("PBEWithHmacSHA512AndAES_256");
		SecretKey sk = skf.generateSecret(pbekeyspec);
		Assertions.hasEnsuredPredicate(sk, "generatedKey");
		Assertions.hasEnsuredPredicate(sk, "randomizedGeneratedKey");
		
		pbekeyspec.clearPassword();
	}
	
	//
	// Backward Error Tracking Tests
	//
	
	@Test
	public void usingNotRandomizedIVForDecryption() throws Exception{
		//Generate Key
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		SecureRandom secureRandom = new SecureRandom();
		int keyBitSize = 128;
		keyGenerator.init(keyBitSize, secureRandom);
		SecretKey secretKey = keyGenerator.generateKey();

		byte[] ivBytes = "notRandomizedIV".getBytes();

		IvParameterSpec iv = new IvParameterSpec(ivBytes); // this does not report an error

		// Create and initialize cipher object
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);

		// encrypt
		byte[] plainText = "ThisIsThePlainText".getBytes("UTF-8");
		byte[] cipherText = cipher.doFinal(plainText);
		
		// all secure
		Assertions.predicateErrors(0);
		Assertions.constraintErrors(0);
		Assertions.typestateErrors(0);
	}
		
	@Test
	public void usingNotRandomizedIVForEncryption() throws Exception{
		//Generate Key
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		SecureRandom secureRandom = new SecureRandom();
		int keyBitSize = 128;
		keyGenerator.init(keyBitSize, secureRandom);
		SecretKey secretKey = keyGenerator.generateKey();

		byte[] ivBytes = "notRandomizedIV".getBytes();

		IvParameterSpec iv = new IvParameterSpec(ivBytes); // this reports a root error
		Assertions.dependentError(0);

		//Create and initialize cipher object
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
		Assertions.dependentError(1, 0); // subsequent error

		// encrypt
		byte[] plainText = "ThisIsThePlainText".getBytes("UTF-8");
		byte[] cipherText = cipher.doFinal(plainText);
		
		Assertions.predicateErrors(2);
		Assertions.constraintErrors(0);
		Assertions.typestateErrors(0);
	}
	
	//
	// Subsequent Error Detection and Mapping Tests
	//
		
	@Test
	public void SEDAMTestKeyStoreWithSignature() throws Exception{
		KeyStore keyStore = KeyStore.getInstance("PKCS12");
		keyStore.load(new FileInputStream(new File("KeySotreFile")), "hardcodedPassword".toCharArray());
		Assertions.dependentError(0);
		Key key = keyStore.getKey("alias", generateRandomPassword());
		
		Assertions.notHasEnsuredPredicate(key, "generatedKey");
		
		Signature signatur = Signature.getInstance("SHA256withRSA");
		signatur.initVerify((PublicKey) key);
		Assertions.dependentError(1, 0);
		
		signatur.verify("signedBytes".getBytes());
	}
	
	@Test
	public void SEDAMTestKeyStoreSSLContext1() throws Exception{
		// generate KeyStore
		KeyStore keyStore = KeyStore.getInstance("PKCS12");
		keyStore.load(new FileInputStream(new File("KeySotreFile")), "hardcodedPassword".toCharArray());
		Assertions.dependentError(0);
		Assertions.notHasEnsuredPredicate(keyStore, "generatedKeyStore");
		
		// generate KeyManager
		KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX");
		kmf.init(keyStore, generateRandomPassword());
		Assertions.dependentError(1, 0);
		
		KeyManager[] kms = kmf.getKeyManagers();
		Assertions.notHasEnsuredPredicate(kms, "generatedKeyManagers");
		
		// generate TrustManager
		TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
		tmf.init(keyStore);
		Assertions.dependentError(2, 0);
		
		TrustManager[] tms = tmf.getTrustManagers();
		Assertions.notHasEnsuredPredicate(kms, "generatedTrustManagers");
		
		// generate SSLContext
		SSLContext ssl = SSLContext.getInstance("TLSv1.2");
		ssl.init(kms, tms, new SecureRandom());
		// one subsequent error for kms, one for tms
		Assertions.dependentError(3, 1); 
		Assertions.dependentError(4, 2);
		
	}
	
	@Test
	public void SEDAMTestKeyStoreSSLContext2() throws Exception{
		// generate KeyStore
		KeyStore keyStore = KeyStore.getInstance("PKCS12");
		keyStore.load(new FileInputStream(new File("KeySotreFile")), "hardcodedPassword".toCharArray());
		Assertions.dependentError(0);
		Assertions.notHasEnsuredPredicate(keyStore, "generatedKeyStore");
		
		// generate KeyManager
		KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX");
		kmf.init(keyStore, generateRandomPassword());
		Assertions.dependentError(1, 0);
		
		KeyManager[] kms = kmf.getKeyManagers();
		Assertions.notHasEnsuredPredicate(kms, "generatedKeyManagers");
		
		// generate TrustManager
		TrustManagerFactory tmf = TrustManagerFactory.getInstance("InsecureAlgorithm");
		Assertions.dependentError(2);
		tmf.init(keyStore);
		Assertions.dependentError(3, 0);
		
		TrustManager[] tms = tmf.getTrustManagers();
		Assertions.notHasEnsuredPredicate(kms, "generatedTrustManagers");
		
		// generate SSLContext
		SSLContext ssl = SSLContext.getInstance("TLSv1.2");
		ssl.init(kms, tms, new SecureRandom());
		
		Assertions.dependentError(4, 1); // subsequent error for kms
		Assertions.dependentError(5, 3, 2); // subsequent error for tms
		
		ssl.createSSLEngine();
	}

	@Test
	public void SEDAMTestInsecurelyGeneratedRSAKeysForEncryption() throws GeneralSecurityException {
		Integer keySize = new Integer(208);
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		RSAKeyGenParameterSpec parameters = new RSAKeyGenParameterSpec(keySize, RSAKeyGenParameterSpec.F0);
		Assertions.dependentError(0);
		
		generator.initialize(parameters, new SecureRandom());
		Assertions.dependentError(1, 0);
		
		KeyPair keyPair = generator.generateKeyPair();
		Assertions.dependentError(2, 1);
		
		Cipher c = Cipher.getInstance("RSA");
		c.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
		Assertions.dependentError(3, 2);
	}
	
	@Test
	public void SEDAMTestInsecurelyGeneratedRSAKeysForDecryption() throws GeneralSecurityException {
		Integer keySize = new Integer(208);
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		RSAKeyGenParameterSpec parameters = new RSAKeyGenParameterSpec(keySize, RSAKeyGenParameterSpec.F0);
		Assertions.dependentError(0);
		
		generator.initialize(parameters, new SecureRandom());
		Assertions.dependentError(1, 0);
		
		KeyPair keyPair = generator.generateKeyPair();
		Assertions.dependentError(2, 1);
		
		Cipher c = Cipher.getInstance("RSA");
		c.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
		Assertions.dependentError(3, 2);
	}
	
	//
	// Dark Predicates are bound to the Objects they are generated on
	//
	
	@Test
	public void DarkPredicateTest1() throws Exception {
		SecureRandom sr1 = SecureRandom.getInstance("InsecureAlgorithm");
		Assertions.dependentError(0);
		SecureRandom sr2 = SecureRandom.getInstance("InsecureAlgorithm");
		Assertions.dependentError(1);
		SecureRandom sr3 = SecureRandom.getInstance("InsecureAlgorithm");
		Assertions.dependentError(2);
		
		byte[] ivBytes1 = new byte[128];
		sr1.nextBytes(ivBytes1);
		
		byte[] ivBytes2 = new byte[128];
		sr2.nextBytes(ivBytes2);
		
		byte[] ivBytes3 = new byte[128];
		sr3.nextBytes(ivBytes3);
		
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		SecretKey secretKey = keyGenerator.generateKey();

		IvParameterSpec iv1 = new IvParameterSpec(ivBytes1); // this reports a root error
		Assertions.dependentError(3, 0);
		
		IvParameterSpec iv1_2 = new IvParameterSpec(ivBytes1); // this reports no error because it is never used
		
		IvParameterSpec iv2 = new IvParameterSpec(ivBytes2); // this reports a root error
		Assertions.dependentError(4, 1);

		//Create and initialize cipher object
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv1);
		Assertions.dependentError(5, 3); // subsequent error
		
		//Create and initialize cipher object
		Cipher cipher2 = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher2.init(Cipher.ENCRYPT_MODE, secretKey, iv2);
		Assertions.dependentError(6, 4); // subsequent error

	}
	
	@Test
	public void DarkPredicateTest2() throws Exception {
		SecureRandom sr1 = SecureRandom.getInstance("InsecureAlgorithm");
		Assertions.dependentError(0);
		SecureRandom sr2 = SecureRandom.getInstance("InsecureAlgorithm");
		Assertions.dependentError(1);
		SecureRandom sr3 = SecureRandom.getInstance("InsecureAlgorithm");
		Assertions.dependentError(2);
		
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(128, sr3);
		Assertions.dependentError(3, 2);
		
		KeyGenerator keyGenerator2 = KeyGenerator.getInstance("AES");
		keyGenerator2.init(128, sr3);
		Assertions.dependentError(4, 2);
		
		KeyGenerator keyGenerator3 = KeyGenerator.getInstance("AES");
		keyGenerator3.init(128, sr1);
		Assertions.dependentError(5, 0);

	}
	
}
