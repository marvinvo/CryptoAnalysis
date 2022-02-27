package crypto.analysis;

import com.google.common.collect.Multimap;

import crypto.extractparameter.CallSiteWithParamIndex;
import crypto.extractparameter.ExtractedValue;
import crypto.rules.CrySLPredicate;

public class DarkPredicate extends EnsuredCrySLPredicate {
	
	private IAnalysisSeed root;
	private boolean isAllowedToBecomeEnsured = true;

	public DarkPredicate(CrySLPredicate predicate,
			Multimap<CallSiteWithParamIndex, ExtractedValue> parametersToValues2, IAnalysisSeed root) {
		super(predicate, parametersToValues2);
		this.root = root;
	}

	public IAnalysisSeed getRoot() {
		return root;
	}
	
	public void setUnallowedToBecomeEnsured() {
		isAllowedToBecomeEnsured = false;
	}
	
	public boolean isAllowedToBecomeEnsured() {
		return isAllowedToBecomeEnsured;
	}

}
