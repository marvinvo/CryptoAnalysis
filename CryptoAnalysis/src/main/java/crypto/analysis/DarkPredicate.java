package crypto.analysis;

import com.google.common.collect.Multimap;

import crypto.extractparameter.CallSiteWithParamIndex;
import crypto.extractparameter.ExtractedValue;
import crypto.rules.CrySLPredicate;

public class DarkPredicate extends EnsuredCrySLPredicate {

	public DarkPredicate(CrySLPredicate predicate,
			Multimap<CallSiteWithParamIndex, ExtractedValue> parametersToValues2) {
		super(predicate, parametersToValues2);
		// TODO Auto-generated constructor stub
	}

}
