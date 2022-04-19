package tests.pattern

import java.security.GeneralSecurityException
import java.security.NoSuchAlgorithmException
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.junit.Test
import crypto.analysis.CrySLRulesetSelector.Ruleset
import test.UsagePatternTestingFramework
import test.assertions.Assertions

class CipherTest extends UsagePatternTestingFramework {
	override protected Ruleset getRuleSet() {
		return Ruleset.JavaCryptographicArchitecture
	}

	@Test def void noInit() throws GeneralSecurityException {
		var Cipher c = Cipher.getInstance("trololo")
		Assertions.extValue(0)
		Assertions.mustNotBeInAcceptingState(c)
		Assertions.notHasEnsuredPredicate(c)
	}

	@Test def void yesInit() throws GeneralSecurityException {
		var Cipher c = Cipher.getInstance("trololo")
		c.init(1, new SecretKeySpec(null, "trololo"))
		Assertions.extValue(0)
		Assertions.mustNotBeInAcceptingState(c)
		Assertions.notHasEnsuredPredicate(c)
	}

	@Test def void useDoFinalInLoop() throws GeneralSecurityException {
		var KeyGenerator keygen = KeyGenerator.getInstance("AES")
		Assertions.extValue(0)
		keygen.init(128)
		Assertions.extValue(0)
		var SecretKey key = keygen.generateKey();
		Assertions.hasEnsuredPredicate(key)
		var Cipher cCipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
		Assertions.extValue(0)
		cCipher.init(Cipher.ENCRYPT_MODE, key)
		Assertions.mustNotBeInAcceptingState(cCipher)
		var byte[] enc = null
		for (var int i = 0; i < 42; i++) {
			enc = cCipher.doFinal("".getBytes())
			Assertions.mustBeInAcceptingState(cCipher)
			Assertions.hasEnsuredPredicate(enc)
		}
		Assertions.mustNotBeInAcceptingState(cCipher)
		Assertions.hasEnsuredPredicate(enc)
	}

	@Test def void caseInsensitiveNames() throws GeneralSecurityException {
		var KeyGenerator keygen = KeyGenerator.getInstance("aes")
		Assertions.extValue(0)
		keygen.init(128)
		Assertions.extValue(0)
		var SecretKey key = keygen.generateKey()
		Assertions.hasEnsuredPredicate(key)
		var Cipher cCipher = Cipher.getInstance("Aes/CbC/pKCS5PADDING")
		Assertions.extValue(0)
		cCipher.init(Cipher.ENCRYPT_MODE, key)
		var byte[] enc = cCipher.doFinal("".getBytes())
		Assertions.mustBeInAcceptingState(cCipher)
		Assertions.hasEnsuredPredicate(enc)
	}

	@Test def void cipherUsagePatternTest1() throws GeneralSecurityException {
		var KeyGenerator keygen = KeyGenerator.getInstance("AES")
		Assertions.extValue(0)
		keygen.init(128)
		Assertions.extValue(0)
		var SecretKey key = keygen.generateKey()
		Assertions.hasEnsuredPredicate(key)
		Assertions.mustBeInAcceptingState(keygen)
		var String string = "AES/CBC/PKCS5Padding"
		var Cipher cCipher = Cipher.getInstance(string)
		Assertions.extValue(0)
		cCipher.init(Cipher.ENCRYPT_MODE, key)
		Assertions.extValue(0)
		var byte[] encText = cCipher.doFinal("".getBytes())
		Assertions.hasEnsuredPredicate(encText)
		Assertions.mustBeInAcceptingState(cCipher)
		cCipher.getIV()
	}

	@Test def void cipherUsagePatternImprecise() throws GeneralSecurityException {
		var SecretKey key = KeyGenerator.getInstance("AES").generateKey()
		Assertions.hasEnsuredPredicate(key)
		var Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding")
		Assertions.extValue(0)
		c.init(Cipher.ENCRYPT_MODE, key)
		var byte[] res = c.doFinal("message".getBytes(), 0, "message".getBytes().length)
		Assertions.mustBeInAcceptingState(c)
		Assertions.hasEnsuredPredicate(res)
	}

	@Test def void cipherUsagePatternTestInsecureKey() throws GeneralSecurityException {
		var byte[] plaintext = "WHAT!?".getBytes()
		var SecretKeySpec encKey = new SecretKeySpec(newByteArrayOfSize(1), "AES")
		Assertions.notHasEnsuredPredicate(encKey)
		var Cipher c = Cipher.getInstance("AES/CBC")
		c.init(1, encKey)
		var String ciphertext = new String(c.doFinal(plaintext))
		Assertions.mustBeInAcceptingState(c)
		Assertions.notHasEnsuredPredicate(ciphertext)
	}

	@Test def void cipherUsagePatternTestInter1() throws GeneralSecurityException {
		var SecretKey key = generateKey()
		Assertions.hasEnsuredPredicate(key)
		encrypt(key)
	}

	@Test def void cipherUsagePatternTestInter2() throws GeneralSecurityException {
		var SecretKey key = generateKey()
		Assertions.hasEnsuredPredicate(key)
		forward(key)
	}

	def private void forward(SecretKey key) throws GeneralSecurityException {
		var SecretKey tmpKey = key
		encrypt(tmpKey)
	}

	@Test def void cipherUsagePatternTestInter3() throws GeneralSecurityException {
		var SecretKey key = generateKey()
		Assertions.hasEnsuredPredicate(key)
		rebuild(key)
	}

	def private void rebuild(SecretKey key) throws GeneralSecurityException {
		var SecretKey tmpKey = new SecretKeySpec(key.getEncoded(), "AES")
		encrypt(tmpKey)
	}

	@Test def void cipherUsagePatternTestInter4() throws GeneralSecurityException {
		var SecretKey key = generateKey()
		Assertions.hasEnsuredPredicate(key)
		wrongRebuild(key)
	}

	def private void wrongRebuild(SecretKey key) throws GeneralSecurityException {
		var SecretKey tmpKey = new SecretKeySpec(key.getEncoded(), "DES")
		Assertions.notHasEnsuredPredicate(tmpKey)
		encryptWrong(tmpKey)
	}

	def private void encryptWrong(SecretKey key) throws GeneralSecurityException {
		var Cipher cCipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
		Assertions.extValue(0)
		cCipher.init(Cipher.ENCRYPT_MODE, key)
		Assertions.extValue(0)
		var byte[] encText = cCipher.doFinal("".getBytes())
		Assertions.notHasEnsuredPredicate(encText)
		Assertions.mustBeInAcceptingState(cCipher)
		cCipher.getIV()
	}

	def private void encrypt(SecretKey key) throws GeneralSecurityException {
		var Cipher cCipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
		Assertions.extValue(0)
		cCipher.init(Cipher.ENCRYPT_MODE, key)
		Assertions.extValue(0)
		var byte[] encText = cCipher.doFinal("".getBytes())
		Assertions.hasEnsuredPredicate(encText)
		Assertions.mustBeInAcceptingState(cCipher)
		cCipher.getIV()
	}

	def private SecretKey generateKey() throws NoSuchAlgorithmException {
		var KeyGenerator keygen = KeyGenerator.getInstance("AES")
		Assertions.extValue(0)
		keygen.init(128)
		Assertions.extValue(0)
		var SecretKey key = keygen.generateKey()
		Assertions.mustBeInAcceptingState(keygen)
		return key
	}

	@Test def void cipherUsagePatternTest1SilentForbiddenMethod() throws GeneralSecurityException {
		var KeyGenerator keygen = KeyGenerator.getInstance("AES")
		Assertions.extValue(0)
		keygen.init(128)
		Assertions.extValue(0)
		var SecretKey key = keygen.generateKey()
		Assertions.hasEnsuredPredicate(key)
		Assertions.mustBeInAcceptingState(keygen)
		var Cipher cCipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
		Assertions.extValue(0)
		cCipher.init(Cipher.DECRYPT_MODE, key)
		Assertions.extValue(0)
		Assertions.callToForbiddenMethod()
		var byte[] encText = cCipher.doFinal("".getBytes())
		Assertions.mustBeInAcceptingState(cCipher)
		Assertions.notHasEnsuredPredicate(cCipher)
		cCipher.getIV()
	}

	@Test def void cipherUsagePatternTest1a() throws GeneralSecurityException {
		var KeyGenerator keygen = KeyGenerator.getInstance("AES")
		Assertions.extValue(0)
		keygen.init(128)
		Assertions.extValue(0)
		var SecretKey key = keygen.generateKey()
		Assertions.hasEnsuredPredicate(key)
		Assertions.mustBeInAcceptingState(keygen)
		var byte[] iv = newByteArrayOfSize(32)
		SecureRandom.getInstanceStrong().nextBytes(iv)
		var IvParameterSpec spec = new IvParameterSpec(iv)
		var Cipher cCipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
		Assertions.extValue(0)
		var int mode = 1
		if (Math.random() % 2 === 0) {
			mode = 2
		}
		cCipher.init(mode, key, spec)
		Assertions.extValue(0)
		var byte[] encText = cCipher.doFinal("".getBytes())
		Assertions.hasEnsuredPredicate(encText)
		Assertions.mustBeInAcceptingState(cCipher)
		cCipher.getIV()
	}

	@Test def void cipherUsagePatternTestIVCor() throws GeneralSecurityException {
		var KeyGenerator keygen = KeyGenerator.getInstance("AES")
		Assertions.extValue(0)
		keygen.init(128)
		Assertions.extValue(0)
		var SecretKey key = keygen.generateKey()
		Assertions.hasEnsuredPredicate(key)
		Assertions.mustBeInAcceptingState(keygen)
		var SecureRandom sr = SecureRandom.getInstanceStrong()
		Assertions.hasEnsuredPredicate(sr)
		var byte[] ivbytes = newByteArrayOfSize(12)
		sr.nextBytes(ivbytes)
		Assertions.hasEnsuredPredicate(ivbytes)
		var IvParameterSpec iv = new IvParameterSpec(ivbytes)
		Assertions.mustBeInAcceptingState(iv)
		Assertions.hasEnsuredPredicate(iv)
		var Cipher cCipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
		Assertions.extValue(0)
		cCipher.init(Cipher.ENCRYPT_MODE, key, iv)
		Assertions.extValue(0)
		var byte[] encText = cCipher.doFinal("".getBytes())
		Assertions.hasEnsuredPredicate(encText)
		Assertions.mustBeInAcceptingState(cCipher)
		cCipher.getIV()
	}

	@Test def void cipherUsagePatternTestIVInCor() throws GeneralSecurityException {
		var KeyGenerator keygen = KeyGenerator.getInstance("AES")
		Assertions.extValue(0)
		keygen.init(128)
		Assertions.extValue(0)
		var SecretKey key = keygen.generateKey()
		Assertions.hasEnsuredPredicate(key)
		Assertions.mustBeInAcceptingState(keygen)
		var byte[] ivbytes = newByteArrayOfSize(12)
		Assertions.notHasEnsuredPredicate(ivbytes)
		var IvParameterSpec iv = new IvParameterSpec(ivbytes)
		Assertions.mustBeInAcceptingState(iv)
		Assertions.notHasEnsuredPredicate(iv)
		var Cipher cCipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
		Assertions.extValue(0)
		cCipher.init(Cipher.ENCRYPT_MODE, key, iv)
		Assertions.extValue(0)
		var byte[] encText = cCipher.doFinal("".getBytes())
		Assertions.notHasEnsuredPredicate(encText)
		Assertions.mustBeInAcceptingState(cCipher)
	}

	@Test def void cipherUsagePatternTestWrongOffsetSize() throws GeneralSecurityException {
		var KeyGenerator keygen = KeyGenerator.getInstance("AES")
		Assertions.extValue(0)
		keygen.init(128)
		Assertions.extValue(0)
		var SecretKey key = keygen.generateKey()
		Assertions.hasEnsuredPredicate(key)
		Assertions.mustBeInAcceptingState(keygen)
		var Cipher cCipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
		Assertions.extValue(0)
		cCipher.init(Cipher.ENCRYPT_MODE, key)
		Assertions.extValue(0)
		val byte[] bytes = "test".getBytes()
		var byte[] encText = cCipher.doFinal(bytes, 200, bytes.length)
		Assertions.extValue(0)
		Assertions.extValue(1)
		Assertions.extValue(2)
		// TODO: Fails for reasons different from the ones I expected.
		cCipher.getIV() // Assertions.mustBeInAcceptingState(cCipher);
		// Assertions.notasEnsuredPredicate(encText);
	}

	@Test def void cipherUsagePatternTestMissingMode() throws GeneralSecurityException {
		var KeyGenerator keygen = KeyGenerator.getInstance("AES")
		Assertions.extValue(0)
		keygen.init(128)
		Assertions.extValue(0)
		var SecretKey key = keygen.generateKey()
		Assertions.hasEnsuredPredicate(key)
		Assertions.mustBeInAcceptingState(keygen)
		var Cipher cCipher = Cipher.getInstance("AES")
		Assertions.extValue(0)
		cCipher.init(Cipher.ENCRYPT_MODE, key)
		Assertions.extValue(0)
		var byte[] encText = cCipher.doFinal("".getBytes())
		Assertions.notHasEnsuredPredicate(encText)
		Assertions.mustBeInAcceptingState(cCipher)
	}

	@Test def void cipherUsagePatternTestWrongPadding() throws GeneralSecurityException {
		var KeyGenerator keygen = KeyGenerator.getInstance("AES")
		Assertions.extValue(0)
		keygen.init(128)
		Assertions.extValue(0)
		var SecretKey key = keygen.generateKey()
		Assertions.hasEnsuredPredicate(key)
		Assertions.mustBeInAcceptingState(keygen)
		var Cipher cCipher = Cipher.getInstance("AES/CBC/NoPadding")
		Assertions.extValue(0)
		cCipher.init(Cipher.ENCRYPT_MODE, key)
		Assertions.extValue(0)
		var byte[] encText = cCipher.doFinal("".getBytes())
		Assertions.notHasEnsuredPredicate(encText)
		Assertions.mustBeInAcceptingState(cCipher)
	}

	@Test def void cipherUsagePatternTest2() throws GeneralSecurityException {
		var KeyGenerator keygen = KeyGenerator.getInstance("AES")
		Assertions.extValue(0)
		keygen.init(129)
		Assertions.extValue(0)
		var SecretKey key = keygen.generateKey()
		Assertions.mustBeInAcceptingState(keygen)
		Assertions.notHasEnsuredPredicate(key)
		var Cipher cCipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
		Assertions.extValue(0)
		cCipher.init(Cipher.ENCRYPT_MODE, key)
		Assertions.extValue(0)
		var byte[] encText = cCipher.doFinal("".getBytes())
		Assertions.notHasEnsuredPredicate(encText)
	}

	@Test def void cipherUsagePatternTest3() throws GeneralSecurityException {
		var KeyGenerator keygen = KeyGenerator.getInstance("AES")
		Assertions.extValue(0)
		keygen.init(128)
		Assertions.extValue(0)
		var SecretKey key = keygen.generateKey()
		Assertions.mustBeInAcceptingState(keygen)
		var Cipher cCipher = Cipher.getInstance("AES")
		cCipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(newByteArrayOfSize(18), "AES"))
		Assertions.extValue(0)
		var byte[] encText = cCipher.doFinal("".getBytes())
		Assertions.mustBeInAcceptingState(cCipher)
		Assertions.notHasEnsuredPredicate(encText)
	}

	@Test def void cipherUsagePatternTestWrongModeExtraVar() throws GeneralSecurityException {
		var String trans = "AES"
		var KeyGenerator keygen = KeyGenerator.getInstance("AES")
		Assertions.extValue(0)
		keygen.init(128)
		Assertions.extValue(0)
		var SecretKey key = keygen.generateKey()
		Assertions.mustBeInAcceptingState(keygen)
		var Cipher cCipher = Cipher.getInstance(trans)
		Assertions.extValue(0)
		cCipher.init(Cipher.ENCRYPT_MODE, key)
		Assertions.extValue(0)
		var byte[] encText = cCipher.doFinal("".getBytes())
		Assertions.mustBeInAcceptingState(cCipher)
		Assertions.notHasEnsuredPredicate(encText)
	}

	@Test def void cipherUsagePatternTest4() throws GeneralSecurityException {
		var KeyGenerator keygen = KeyGenerator.getInstance("AES")
		Assertions.extValue(0)
		keygen.init(128)
		Assertions.extValue(0)
		var SecretKey key = keygen.generateKey()
		Assertions.mustBeInAcceptingState(keygen)
		var Cipher cCipher = Cipher.getInstance("Blowfish")
		Assertions.extValue(0)
		cCipher.init(Cipher.ENCRYPT_MODE, key)
		Assertions.extValue(0)
		var byte[] encText = cCipher.doFinal("".getBytes())
		Assertions.mustBeInAcceptingState(cCipher)
		Assertions.notHasEnsuredPredicate(encText)
	}

	@Test def void cipherUsagePatternTest5() throws GeneralSecurityException {
		val byte[] msgAsArray = "Message".getBytes()
		var KeyGenerator keygenEnc = KeyGenerator.getInstance("AES")
		Assertions.extValue(0)
		keygenEnc.init(128)
		Assertions.extValue(0)
		var SecretKey keyEnc = keygenEnc.generateKey()
		Assertions.mustBeInAcceptingState(keygenEnc)
		var Cipher cCipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
		Assertions.extValue(0)
		cCipher.init(Cipher.ENCRYPT_MODE, keyEnc)
		Assertions.extValue(0)
		var byte[] encText = cCipher.doFinal(msgAsArray)
		cCipher.getIV()
		Assertions.mustBeInAcceptingState(cCipher)
		Assertions.hasEnsuredPredicate(encText)
		var KeyGenerator keygenMac = KeyGenerator.getInstance("HmacSHA256")
		var SecretKey keyMac = keygenMac.generateKey()
		val Mac hMacSHA256 = Mac.getInstance("HmacSHA256")
		Assertions.extValue(0)
		hMacSHA256.init(keyMac)
		var byte[] macced = hMacSHA256.doFinal(msgAsArray)
		Assertions.mustNotBeInAcceptingState(hMacSHA256)
		Assertions.notHasEnsuredPredicate(macced)
	}

	@Test def void cipherUsagePatternTest6() throws GeneralSecurityException {
		var SecureRandom keyRand = SecureRandom.getInstanceStrong()
		var KeyGenerator keygen = KeyGenerator.getInstance("AES")
		Assertions.extValue(0)
		Assertions.hasEnsuredPredicate(keyRand)
		keygen.init(128, keyRand)
		Assertions.extValue(0)
		var SecretKey key = keygen.generateKey()
		Assertions.mustBeInAcceptingState(keygen)
		var SecureRandom encRand = SecureRandom.getInstanceStrong()
		var Cipher cCipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
		Assertions.extValue(0)
		cCipher.init(Cipher.ENCRYPT_MODE, key, encRand)
		Assertions.extValue(0)
		var byte[] encText = cCipher.doFinal("".getBytes())
		Assertions.mustBeInAcceptingState(cCipher)
		Assertions.hasEnsuredPredicate(encText)
		cCipher.getIV()
	}

	@Test def void cipherUsagePatternTest7() throws GeneralSecurityException {
		var SecureRandom rand = SecureRandom.getInstanceStrong()
		var KeyGenerator keygen = KeyGenerator.getInstance("AES")
		Assertions.extValue(0)
		keygen.init(128)
		Assertions.extValue(0)
		var SecretKey key = keygen.generateKey()
		Assertions.mustBeInAcceptingState(keygen)
		var Cipher cCipher = Cipher.getInstance("Blowfish")
		Assertions.extValue(0)
		cCipher.init(Cipher.ENCRYPT_MODE, key, rand)
		Assertions.extValue(0)
		var byte[] encText = cCipher.doFinal("".getBytes())
		Assertions.mustBeInAcceptingState(cCipher)
		Assertions.notHasEnsuredPredicate(encText)
	}

	@Test def void cipherUsagePatternTest7b() throws GeneralSecurityException {
		var SecureRandom encRand = SecureRandom.getInstanceStrong()
		var KeyGenerator keygen = KeyGenerator.getInstance("AES")
		Assertions.extValue(0)
		keygen.init(128, null)
		Assertions.extValue(0)
		var SecretKey key = keygen.generateKey()
		Assertions.mustBeInAcceptingState(keygen)
		Assertions.notHasEnsuredPredicate(key)
		var Cipher cCipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
		Assertions.extValue(0)
		cCipher.init(Cipher.ENCRYPT_MODE, key, encRand)
		Assertions.extValue(0)
		var byte[] encText = cCipher.doFinal("".getBytes())
		Assertions.mustBeInAcceptingState(cCipher)
		Assertions.notHasEnsuredPredicate(encText)
	}

	@Test def void cipherUsagePatternTest8() throws GeneralSecurityException {
		var String aesString = "AES"
		var KeyGenerator keygen = KeyGenerator.getInstance(aesString)
		Assertions.extValue(0)
		var int keySize = 128
		var int a = keySize
		keygen.init(a)
		Assertions.extValue(0)
		var SecretKey key = keygen.generateKey()
		Assertions.hasEnsuredPredicate(key)
		Assertions.mustBeInAcceptingState(keygen)
		var Cipher cCipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
		Assertions.extValue(0)
		cCipher.init(Cipher.ENCRYPT_MODE, key)
		Assertions.extValue(0)
		var byte[] encText = cCipher.doFinal("".getBytes())
		cCipher.getIV()
		Assertions.hasEnsuredPredicate(encText)
		Assertions.mustBeInAcceptingState(cCipher)
	}

	@Test def void cipherUsagePatternTest9() throws GeneralSecurityException {
		var KeyGenerator keygen = KeyGenerator.getInstance("AES")
		Assertions.extValue(0)
		keygen.init(1)
		Assertions.extValue(0)
		var SecretKey key = keygen.generateKey()
		Assertions.notHasEnsuredPredicate(key)
		Assertions.mustBeInAcceptingState(keygen)
		var Cipher cCipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
		Assertions.extValue(0)
		cCipher.init(Cipher.ENCRYPT_MODE, key)
		Assertions.extValue(0)
		var byte[] encText = cCipher.doFinal("".getBytes())
		Assertions.notHasEnsuredPredicate(encText)
		Assertions.mustBeInAcceptingState(cCipher)
	}
}
