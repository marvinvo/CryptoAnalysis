package test.assertions;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.common.collect.Maps;
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
	private Map<Integer,List<AbstractError>> idToErrors = Maps.newHashMap();
	private List<DependentErrorAssertion> listener = Lists.newArrayList();
	
	public DependentErrorAssertion(Stmt pred, int thisAssertionID, int... precedingAssertionIDs) {
		errorLocation = pred;
		this.thisAssertionID = thisAssertionID;
		this.precedingAssertionIDs = precedingAssertionIDs;
	}

	@Override
	public boolean isSatisfied() {
		if(extractedErrors.isEmpty()) {
			return false;
		}
		nextExtractedError:
		for(AbstractError e: this.extractedErrors) {
			for(int id: this.precedingAssertionIDs) {
				if(!this.idToErrors.containsKey(id) || !this.idToErrors.get(id).stream().anyMatch(preceding -> e.getRootErrors().contains(preceding))){
					continue nextExtractedError;
				}
			}
			return true;
		}
		return false;
		
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
		List<AbstractError> errorsWithMatchingId = this.idToErrors.getOrDefault(errorNr, Lists.newArrayList());
		errorsWithMatchingId.add(error);
		this.idToErrors.put(errorNr, errorsWithMatchingId);
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
