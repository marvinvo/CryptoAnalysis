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

public class BCSubsequentErrorTests extends UsagePatternTestingFramework{
	
	@Override
	protected CryptoScannerSettings getSettings() {
		CryptoScannerSettings settings = new CryptoScannerSettings();
		settings.setSubsequentErrorDetection(true);
		return settings;
	}
	
	@Override
	protected Ruleset getRuleSet() {
		return Ruleset.BouncyCastle;
	}
	
	public static class Constants {
		
		public static BigInteger n = new BigInteger("62771017353866");
		
		public static ECCurve.Fp curve = new ECCurve.Fp(
								        new BigInteger("2343"),
								        new BigInteger("2343"),
								        new BigInteger("2343"),
								        n, ECConstants.ONE);
		
		public static ECDomainParameters params = new ECDomainParameters(
	            curve,
	            curve.decodePoint(Hex.decode("03188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012")), // G
	            n);
		
		public static ECPublicKeyParameters pubKeyValid = new ECPublicKeyParameters(
	            curve.decodePoint(Hex.decode("0262b12d")), // Q
	            params);
		
		public static ECPrivateKeyParameters priKey = new ECPrivateKeyParameters(
			    new BigInteger("6510567709"), // d
			    params);
		
	}

	@Test
	public void testFive() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException{
			String point = "029348203948";
			ECDomainParameters params = new ECDomainParameters(Constants.curve, Constants.curve.decodePoint(Hex.decode(point)), Constants.n, Constants.n, Hex.decode(point));
			Assertions.createsARootError();
			ECPublicKeyParameters pubKey = new ECPublicKeyParameters(Constants.curve.decodePoint(Hex.decode(point)), params);
			Assertions.createsASubsequentError();
			ParametersWithRandom pubKeyRand = new ParametersWithRandom(pubKey, null);
			Assertions.createsASubsequentError();
			Assertions.createsARootError();
		
	}
	
}
