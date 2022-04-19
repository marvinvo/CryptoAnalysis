package crypto.analysis.errors;

import java.util.Collection;

import com.google.common.collect.Sets;

import crypto.rules.CrySLRule;

public class AlternativeRequiredPredicateError extends AbstractError{

	Collection<RequiredPredicateError> alternativeErrors = Sets.newHashSet();
	
	public AlternativeRequiredPredicateError(CrySLRule rule, RequiredPredicateError... reqPredErrors) {
		super(null, rule);
		for(RequiredPredicateError e: reqPredErrors) {
			alternativeErrors.add(e);
		}
	}

	@Override
	public String toErrorMarkerString() {
		String msg = "One of the following Errors must be fixed: \n";
		for(RequiredPredicateError e: alternativeErrors) {
			msg += e.toErrorMarkerString();
		}
		return msg;
	}
	
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		for(RequiredPredicateError e: alternativeErrors) {
			result = prime * result + e.hashCode();
		}
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (!super.equals(obj))
			return false;
		if (getClass() != obj.getClass())
			return false;
		AlternativeRequiredPredicateError other = (AlternativeRequiredPredicateError) obj;
		// TODO
		return true;
	}

	@Override
	public void accept(ErrorVisitor visitor) {
		// TODO Auto-generated method stub
		
	}

}
