package crypto.reporting;

import java.io.File;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;

import crypto.analysis.IAnalysisSeed;
import crypto.exceptions.CryptoAnalysisException;
import crypto.rules.CrySLRule;

public class CommandLineReporter extends ErrorMarkerListener {

	private File reportFolder;
	private Collection<CrySLRule> rules;
	private Collection<IAnalysisSeed> objects = new HashSet<>();
	private String analysisReport;

	public File getReportFolder() {
		return reportFolder;
	}

	public void setReportFolder(File reportFolder) {
		this.reportFolder = reportFolder;
	}
	
	/**
	 * Creates {@link CommandLineReporter} a constructor with output as parameter
	 * 
	 * @param reportDir a {@link String} path giving the location of the report directory
	 * @param rules {@link CrySLRule} {@link List} the rules with which the project is analyzed
	 */
	public CommandLineReporter(Optional<File> reportFolder) throws CryptoAnalysisException {
		if(!reportFolder.isPresent() || reportFolder ==null) {
			throw new CryptoAnalysisException("Report directory not specified");
		}
		this.reportFolder = reportFolder.get();
	}
	
	/**
	 * Creates {@link CommandLineReporter} a constructor with reportDir and rules as parameter
	 * 
	 * @param reportDir a {@link String} path giving the location of the report directory
	 * @param rules {@link CrySLRule} {@link List} the rules with which the project is analyzed
	 */
	@Deprecated
	public CommandLineReporter(String reportDir, List<CrySLRule> rules) {
		this.setReportFolder((reportDir != null ? new File(reportDir) : null));
		this.rules = rules;
	}
	
	/**
	 * Creates {@link CommandLineReporter} a constructor with reportDir and rules as parameter
	 * 
	 * @param reportDir a {@link String} path giving the location of the report directory
	 * @param rules {@link CrySLRule} {@link Collection} the rules with which the project is analyzed
	 */
	public CommandLineReporter(String reportDir, Collection<CrySLRule> rules) {
		this.setReportFolder((reportDir != null ? new File(reportDir) : null));
		this.rules = rules;
	}

	/**
	 * Creates {@link CommandLineReporter} a constructor with rules as parameter
	 * 
	 * @param rules {@link CrySLRule} {@link List} the rules with which the project is analyzed
	 */
	@Deprecated
	public CommandLineReporter(List<CrySLRule> rules) {
		this.rules = rules;
	}
	
	/**
	 * Creates {@link CommandLineReporter} a constructor with rules as parameter
	 * 
	 * @param rules {@link CrySLRule} {@link Collection} the rules with which the project is analyzed
	 */
	public CommandLineReporter(Collection<CrySLRule> rules) {
		this.rules = rules;
	}
	
	@Override
	public void discoveredSeed(IAnalysisSeed object) {
		this.objects.add(object);
	}
	@Override
	public void afterAnalysis() {
		this.analysisReport = ReporterHelper.generateReport(this.rules, this.objects, this.secureObjects, this.errorMarkers, this.errorMarkerCount);
		System.out.println(analysisReport);
	}
}
