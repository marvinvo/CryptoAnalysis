package tests.subsequenterrors;

import crypto.analysis.CrySLRulesetSelector.Ruleset;
import crypto.analysis.CryptoScannerSettings;
import test.UsagePatternTestingFramework;

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
	
	/*
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
	*/
	
	
}
