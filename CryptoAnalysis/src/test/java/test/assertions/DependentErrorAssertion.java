package test.assertions;

import java.util.Collection;
import java.util.List;
import java.util.Set;

import com.google.inject.internal.util.Lists;
import com.google.inject.internal.util.Sets;

import boomerang.jimple.Statement;
import crypto.analysis.errors.AbstractError;
import crypto.analysis.errors.RequiredPredicateError;
import soot.jimple.Stmt;
import test.Assertion;

public class DependentErrorAssertion implements Assertion{
	
	private Stmt errorLocation;
	private List<AbstractError> extractedErrors = Lists.newArrayList();
	private int thisAssertionID;
	private int[] precedingAssertionIDs;
	private List<AbstractError> requiredToBePreceding = Lists.newArrayList();
	private List<DependentErrorAssertion> listener = Lists.newArrayList();
	
	public DependentErrorAssertion(Stmt pred, int thisAssertionID, int... precedingAssertionIDs) {
		errorLocation = pred;
		this.thisAssertionID = thisAssertionID;
		this.precedingAssertionIDs = precedingAssertionIDs;
	}

	@Override
	public boolean isSatisfied() {
		return !extractedErrors.isEmpty() && extractedErrors.stream().anyMatch(e -> requiredToBePreceding.stream().allMatch(preceding -> e.getRootErrors().contains(preceding)));
	}

	@Override
	public boolean isImprecise() {
		// TODO Auto-generated method stub
		return false;
	}
	
	public void registerListeners(Collection<Assertion> assertions) {
		assertions.forEach(ass -> listener.add((DependentErrorAssertion)ass));
	}
	
	public void addErrorOfOtherLocations(AbstractError error, int errorNr) {
		for(int id: this.precedingAssertionIDs) {
			if(id == errorNr) {
				this.requiredToBePreceding.add(error);
				return;
			}
		}
	}

	public void addError(AbstractError error) {
		if(error.getErrorLocation().getUnit().get() == errorLocation) {
			extractedErrors.add(error);
			listener.forEach(ass -> ass.addErrorOfOtherLocations(error, thisAssertionID));
		}
	}
	
	@Override
	public String toString() {
		return extractedErrors.isEmpty()
				? "Expected an error @ " + errorLocation + " but found none." 
				: extractedErrors.toString() + " @ " + errorLocation + " is not a subsequent error.";
	}

}
