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

import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import crypto.analysis.CryptoScannerSettings;
import crypto.analysis.CrySLRulesetSelector.Ruleset;
import test.UsagePatternTestingFramework;
import test.assertions.Assertions;

public class JCASubsequentErrorTests extends UsagePatternTestingFramework{
	
	@Override
	protected CryptoScannerSettings getSettings() {
		CryptoScannerSettings settings = new CryptoScannerSettings();
		settings.setSubsequentErrorDetection(true);
		return settings;
	}
	
	@Override
	protected Ruleset getRuleSet() {
		return Ruleset.JavaCryptographicArchitecture;
	}
	
	@Test
	public void test1() throws GeneralSecurityException {
		Integer keySize = new Integer(208);
		KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
		RSAKeyGenParameterSpec parameters = new RSAKeyGenParameterSpec(keySize, RSAKeyGenParameterSpec.F0);
		Assertions.createsARootError();
		generator.initialize(parameters, new SecureRandom());
		Assertions.createsASubsequentError();
		KeyPair keyPair = generator.generateKeyPair();
		Cipher c = Cipher.getInstance("RSA");
		c.init(Cipher.ENCRYPT_MODE, keyPair.getPrivate());
		Assertions.createsASubsequentError();
	}
	
	public char[] generateRandomPassword() {
		SecureRandom rnd = new SecureRandom();
		char[] defaultKey = new char[20];
		for (int i = 0; i < 20; i++) {
			defaultKey[i] = (char) (rnd.nextInt(26) + 'a');
		}
		return defaultKey;
	}
	
	@Test
	public void test2() throws Exception{
		final byte[] salt = new byte[32];

		final PBEKeySpec pbekeyspec = new PBEKeySpec(generateRandomPassword(), salt, 65000, 128);
		Assertions.createsARootError();

		final SecretKeyFactory secFac = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		
		SecretKey tmpKey = secFac.generateSecret(pbekeyspec);
		Assertions.createsASubsequentError();
		
		pbekeyspec.clearPassword();
		
		byte[] keyMaterial = tmpKey.getEncoded();
		final SecretKeySpec actKey = new SecretKeySpec(keyMaterial, "AES");
	}
	
	
}
