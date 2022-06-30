package crypto.analysis;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import com.google.common.collect.Lists;
import com.google.common.collect.Multimap;
import com.google.common.collect.Sets;

import crypto.analysis.errors.AbstractError;
import crypto.analysis.errors.IncompleteOperationError;
import crypto.analysis.errors.TypestateError;
import crypto.extractparameter.CallSiteWithParamIndex;
import crypto.extractparameter.ExtractedValue;
import crypto.rules.CrySLCondPredicate;
import crypto.rules.CrySLPredicate;

public class DarkPredicate extends EnsuredCrySLPredicate {
	
	private IAnalysisSeed generatingSeed;
	private DarkPredicateType type;

	public DarkPredicate(CrySLPredicate predicate,
			Multimap<CallSiteWithParamIndex, ExtractedValue> parametersToValues2, IAnalysisSeed generatingSeed, DarkPredicateType type) {
		super(predicate, parametersToValues2);
		this.generatingSeed = generatingSeed;
		this.type = type;
	}

	public IAnalysisSeed getGeneratingSeed() {
		return generatingSeed;
	}

	public enum DarkPredicateType{
		GeneratingStateIsNeverReached,
		ConstraintsAreNotSatisfied,
		ConditionIsNotSatisfied
	}
	
	public DarkPredicateType getType() {
		return type;
	}
	
	/**
	 * Node: Errors are only in complete count at the end of the analysis.
	 * @return
	 */
	public List<AbstractError> getPrecedingErrors(){
		List<AbstractError> results = Lists.newArrayList();
		List<AbstractError> allErrors = generatingSeed.getErrors();
		switch(type) {
			case GeneratingStateIsNeverReached:
				List<AbstractError> typestateErrors = allErrors.stream().filter(e -> (e instanceof IncompleteOperationError || e instanceof TypestateError)).collect(Collectors.toList());
				if(typestateErrors.isEmpty()) {
					// seed object has no typestate errors that might be resposible for this dark predicate
					// TODO: report new info error type to report, 
					// 		that the seeds object could potentially ensure the missing predicate which might cause further subsequent errors
					// 		but therefore requires a call to the predicate generating statement
				}
				
				// TODO: check whether the generating state is not reached due to a typestate error
				return allErrors;
				
			case ConstraintsAreNotSatisfied:
				// generating state was reached but constraints are not satisfied
				// thus, return all constraint & required predicate errors
				return allErrors.stream().filter(e -> !(e instanceof IncompleteOperationError || e instanceof TypestateError)).collect(Collectors.toList());
			case ConditionIsNotSatisfied:
				// generating state was reached but the predicates condition is not satisfied
				// thus, return all errors that causes the condition to be not satisfied
				
		}
		return results;
	}
}
