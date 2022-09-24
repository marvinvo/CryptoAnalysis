package issueccsast;

import java.io.FileInputStream;
import java.lang.Exception;
import java.security.KeyStore;

public class Main {

	public static void main(String[] args) throws Exception {
		KeyStore ks = KeyStore.getInstance("test");
		ks.load(new FileInputStream("Test"), "test".toCharArray());
	}

}
