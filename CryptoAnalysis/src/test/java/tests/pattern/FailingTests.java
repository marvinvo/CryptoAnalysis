package tests.pattern;

import java.io.File;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Ignore;
import org.junit.Test;

import crypto.analysis.CrySLRulesetSelector.Ruleset;
import test.UsagePatternTestingFramework;
import test.assertions.Assertions;

public class FailingTests extends UsagePatternTestingFramework {

	@Override
	protected Ruleset getRuleSet() {
		return Ruleset.JavaCryptographicArchitecture;
	}
	
	//
	// ISSUES IN CryptoAnalysis
	//
	
	@Test
	public void NegatingPredicatesOccasionallyNotWork() throws Exception {
		KeyGenerator keygen = KeyGenerator.getInstance("AES");
		keygen.init(256);
		SecretKey key = keygen.generateKey();
		Assertions.hasEnsuredPredicate(key);
		
		key.destroy();
		Assertions.notHasEnsuredPredicate(key);

		Cipher cCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cCipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] encText = cCipher.doFinal("test".getBytes());
		Assertions.notHasEnsuredPredicate(encText); // fails (false negative)
	}
	
	@Test
	public void falsePositiveExampleForCipherDecryptionMode() throws Exception {
		byte[] readFromEncryptedCipher = new byte[32];
		KeyGenerator keygen = KeyGenerator.getInstance("AES");
		keygen.init(256);
		SecretKey key = keygen.generateKey();

		Cipher cCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cCipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(readFromEncryptedCipher));
		byte[] encText = cCipher.doFinal("test".getBytes());
		Assertions.predicateErrors(0); // fails
		Assertions.hasEnsuredPredicate(encText); // fails
	}
	
	@Test
	public void requiredPredicatesAreNotValidatedIfNoPredicateEnsuringState() throws Exception {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("DH");
		kpg.initialize(1024); // constraint error
		PrivateKey pk = kpg.generateKeyPair().getPrivate(); // insecure PrivateKey
		
		
		KeyAgreement ka = KeyAgreement.getInstance("DH");
		ka.init(pk, new SecureRandom()); // this reports no RequiredPredicateError
		Assertions.predicateErrors(2); // Assertion for new rule set: this does actually report a RequiredPredicateError for the KeyPair aswell. 
		// Assertions.predicateErrors(1); // Assertion for old rule set
	}
	
	@Test
	public void stateMachineBuilderExampleIssue() throws Exception {
		byte[] msg1 = ("demo msg").getBytes();
		KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
		g.initialize(2048);
		KeyPair kp = g.generateKeyPair();

		Cipher enc = Cipher.getInstance("RSA/ECB/NoPadding");
		enc.init(Cipher.ENCRYPT_MODE, kp.getPublic());
		
		enc.doFinal(msg1);
		enc.doFinal(msg1); // reports a typestate error for this, but the usage is actually allowed and specified.
		Assertions.typestateErrors(0);
	}
	
	//
	// ISSUES IN CrySL RULES
	//
	
	@Test
	public void missingKeySpecDifferentiationInKeyFactoryRule() throws Exception {
		// RSA Key Specs are yet not specified in CrySL rules and thus does not ensure a predicate
		RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(new BigInteger("102938102938012983"), new BigInteger("102938102938012983"));
		RSAPrivateKeySpec privKeySpec = new RSAPrivateKeySpec(new BigInteger("102938102938012983"), new BigInteger("102938102938012983"));
		KeyFactory kf = KeyFactory.getInstance("RSA");
		PrivateKey privK = kf.generatePrivate(privKeySpec); // RequiredPredicateError
		PublicKey pubK = kf.generatePublic(pubKeySpec); // RequiredPredicateError
		Assertions.predicateErrors(2);
	}
	
}
