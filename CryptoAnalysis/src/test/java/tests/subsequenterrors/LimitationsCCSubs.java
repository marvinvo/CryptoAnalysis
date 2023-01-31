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
import java.security.spec.X509EncodedKeySpec;

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
	
	@Test
	public void missingErrorsWhenCallingAMethodMultipleTimes() throws Exception {
		X509EncodedKeySpec keySpec1 = new X509EncodedKeySpec("insecureKeyBytes".getBytes()); // RequiredPredicateError
		Assertions.dependentError(0); // passes
		X509EncodedKeySpec keySpec2 = new X509EncodedKeySpec("insecureKeyBytes".getBytes()); // RequiredPredicateError
		Assertions.dependentError(1); // passes
		
		Assertions.notHasEnsuredPredicate(keySpec1, "speccedKey");
		Assertions.notHasEnsuredPredicate(keySpec2, "speccedKey");
		
		KeyFactory kf = KeyFactory.getInstance("RSA");
		PublicKey pubkey1 = kf.generatePublic(keySpec1); // RequiredPredicateError
		Assertions.dependentError(2, 0); // passes
		Assertions.notHasEnsuredPredicate(pubkey1);
		// generating another public key is not a typestate misuse, but the additional RequiredPredicateError is not reported
		PublicKey pubkey2 = kf.generatePublic(keySpec2); // missing RequiredPredicateError
		Assertions.dependentError(3, 1); // fails due to missing error
		Assertions.notHasEnsuredPredicate(pubkey2);
		
		Assertions.predicateErrors(4); // fails
	}
	
	
	
}
