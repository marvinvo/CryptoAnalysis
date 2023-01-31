package test.assertions;

import boomerang.jimple.Val;
import crypto.analysis.DarkPredicate;
import crypto.analysis.EnsuredCrySLPredicate;
import soot.jimple.Stmt;
import test.Assertion;

public class NotHasEnsuredPredicateAssertion implements Assertion {

	private Stmt stmt;
	private Val val;
	private boolean imprecise = false;
	private String predName = null;

	public NotHasEnsuredPredicateAssertion(Stmt stmt, Val val) {
		this.stmt = stmt;
		this.val = val;
	}
	
	public NotHasEnsuredPredicateAssertion(Stmt stmt, Val val, String predName) {
		this(stmt, val);
		this.predName = predName;
	}
	
	public Val getAccessGraph() {
		return val;
	}

	@Override
	public boolean isSatisfied() {
		return true;
	}

	@Override
	public boolean isImprecise() {
		return imprecise;
	}


	public Stmt getStmt() {
		return stmt;
	}

	public void reported(Val value, EnsuredCrySLPredicate pred) {
		if(value.equals(val) && !(pred instanceof DarkPredicate) &&
				(this.predName == null || pred.getPredicate().getPredName().equals(this.predName))){
			imprecise = true;
		}
	}

	@Override
	public String toString() {
		return this.predName == null ? 
				"Did not expect a predicate for "+ val +" @ " + stmt 
				: "Did not expect "+ this.predName +" ensured on "+ val +" @ " + stmt;  
	}
}
