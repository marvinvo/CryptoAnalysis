package crypto.analysis;

public class CryptoScannerSettings {
	
	private boolean subsequentErrorDetection;
	
	public CryptoScannerSettings() {
		setSubsequentErrorDetection(false);
	}
	
	public boolean isSubsequentErrorDetection() {
		return this.subsequentErrorDetection;
	}
	
	public void setSubsequentErrorDetection(boolean subsequentErrorDetection) {
		this.subsequentErrorDetection = subsequentErrorDetection;
	}
	
}
