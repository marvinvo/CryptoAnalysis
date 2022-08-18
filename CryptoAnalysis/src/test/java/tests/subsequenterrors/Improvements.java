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
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Test;

import crypto.analysis.CryptoScannerSettings;
import crypto.analysis.CrySLRulesetSelector.Ruleset;
import test.UsagePatternTestingFramework;
import test.assertions.Assertions;

public class Improvements extends UsagePatternTestingFramework{
	
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
	
	// BUG IN CCSAST
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
		Assertions.predicateErrors(1); // fails
	}
	
	// CAUSES BUG IN CCSUBS
	@Test
	public void multiplePrecedingErrorsFailsBecauseOfCCSAST() throws Exception{
		SecureRandom sr = SecureRandom.getInstance("insecureAlg"); // root error
		byte[] insecureBytes = new byte[] {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
		Assertions.dependentError(0);
		sr.setSeed(insecureBytes); // root error
		Assertions.dependentError(1);
		KeyGenerator kg = KeyGenerator.getInstance("AES");
		kg.init(128, sr); // subsequent error
		Assertions.dependentError(2,1,0);
		SecretKey key = kg.generateKey();
	}
	
	@Test
	public void predicatesAreBoundToGeneratingStateCondition() throws Exception {
		KeyFactory kf = KeyFactory.getInstance("insecureAlg");
		PrivateKey privk = kf.generatePrivate(new SecretKeySpec(new byte[32], "AES"));
		PublicKey pubk = kf.generatePublic(new SecretKeySpec(new byte[32], "AES"));
		
	}
	
	
}
