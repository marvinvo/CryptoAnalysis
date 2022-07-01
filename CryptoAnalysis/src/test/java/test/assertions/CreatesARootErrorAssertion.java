package test.assertions;

import java.util.List;
import java.util.Set;

import com.google.inject.internal.util.Lists;
import com.google.inject.internal.util.Sets;

import boomerang.jimple.Statement;
import crypto.analysis.errors.AbstractError;
import crypto.analysis.errors.RequiredPredicateError;
import soot.jimple.Stmt;
import test.Assertion;

public class CreatesARootErrorAssertion implements Assertion{
	
	private Stmt errorLocation;
	private List<AbstractError> extractedErrors = Lists.newArrayList();
	
	public CreatesARootErrorAssertion(Stmt pred) {
		errorLocation = pred;
	}

	@Override
	public boolean isSatisfied() {
		return !extractedErrors.isEmpty() && extractedErrors.stream().anyMatch(e -> e.getRootErrors().isEmpty());
	}

	@Override
	public boolean isImprecise() {
		// TODO Auto-generated method stub
		return false;
	}

	public void addError(AbstractError error) {
		if(error.getErrorLocation().getUnit().get() == errorLocation) {
			extractedErrors.add(error);
		}
	}
	
	@Override
	public String toString() {
		return extractedErrors.isEmpty()
				? "Expected an error @ " + errorLocation + " but found none." 
				: extractedErrors.toString() + " @ " + errorLocation + " is not a root error.";
	}

}
