package test.assertions;

import boomerang.jimple.Val;
import crypto.analysis.DarkPredicate;
import crypto.analysis.EnsuredCrySLPredicate;
import soot.jimple.Stmt;
import test.Assertion;

public class HasEnsuredPredicateAssertion implements Assertion {

	private Stmt stmt;
	private Val val;
	private boolean satisfied;
	private String predName = null;

	public HasEnsuredPredicateAssertion(Stmt stmt,  Val val) {
		this.stmt = stmt;
		this.val = val;
	}
	
	public HasEnsuredPredicateAssertion(Stmt stmt, Val val, String predName) {
		this(stmt, val);
		this.predName = predName;
	}
	
	public Val getAccessGraph() {
		return val;
	}

	@Override
	public boolean isSatisfied() {
		return satisfied;
	}

	@Override
	public boolean isImprecise() {
		return false;
	}


	public Stmt getStmt() {
		return stmt;
	}

	public void reported(Val seed, EnsuredCrySLPredicate pred) {
		if(seed.equals(val) && !(pred instanceof DarkPredicate) && 
				(this.predName == null || pred.getPredicate().getPredName().equals(this.predName)))
			satisfied = true;
	}

	@Override
	public String toString() {
		return this.predName == null ? 
				"Expected a predicate for "+ val +" @ " + stmt
				: "Expected "+ this.predName +" ensured on "+ val +" @ " + stmt;  
	}
}
