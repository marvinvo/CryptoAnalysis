package test.assertions;

import java.util.Set;

import com.google.inject.internal.util.Sets;

import boomerang.jimple.Statement;
import crypto.analysis.errors.AbstractError;
import crypto.analysis.errors.RequiredPredicateError;
import soot.jimple.Stmt;
import test.Assertion;

public class CreatesASubsequentErrorAssertion implements Assertion{
	
	private Stmt errorLocation;
	private AbstractError extractedError;
	
	public CreatesASubsequentErrorAssertion(Stmt pred) {
		errorLocation = pred;
	}

	@Override
	public boolean isSatisfied() {
		return extractedError != null && !extractedError.getRootErrors().isEmpty();
	}

	@Override
	public boolean isImprecise() {
		// TODO Auto-generated method stub
		return false;
	}

	public void addError(AbstractError error) {
		if(error.getErrorLocation().getUnit().get() == errorLocation) {
			extractedError = error;
		}
	}
	
	@Override
	public String toString() {
		return extractedError == null 
				? "Expected an error @ " + errorLocation + " but found none." 
				: extractedError + " @ " + errorLocation + " is not a subsequent error.";
	}

}
