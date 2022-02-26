package crypto.predicates;

import java.util.AbstractMap.SimpleEntry;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.stream.Collectors;

import com.google.common.collect.HashBasedTable;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import com.google.common.collect.Table;
import com.google.common.collect.Table.Cell;
import boomerang.jimple.Statement;
import boomerang.jimple.Val;
import boomerang.results.ForwardBoomerangResults;
import crypto.analysis.AlternativeReqPredicate;
import crypto.analysis.AnalysisSeedWithSpecification;
import crypto.analysis.ClassSpecification;
import crypto.analysis.CryptoScanner;
import crypto.analysis.DarkPredicate;
import crypto.analysis.EnsuredCrySLPredicate;
import crypto.analysis.IAnalysisSeed;
import crypto.analysis.RequiredCrySLPredicate;
import crypto.analysis.ResultsHandler;
import crypto.analysis.errors.AbstractError;
import crypto.analysis.errors.ErrorWithObjectAllocation;
import crypto.analysis.errors.PredicateContradictionError;
import crypto.analysis.errors.RequiredPredicateError;
import crypto.extractparameter.CallSiteWithExtractedValue;
import crypto.extractparameter.CallSiteWithParamIndex;
import crypto.interfaces.ISLConstraint;
import crypto.rules.CrySLConstraint;
import crypto.rules.CrySLPredicate;
import crypto.rules.CrySLRule;
import soot.SootClass;
import soot.SootMethod;
import soot.Unit;
import soot.Value;
import soot.jimple.AssignStmt;
import soot.jimple.InstanceInvokeExpr;
import soot.jimple.InvokeExpr;
import soot.jimple.StaticInvokeExpr;
import soot.jimple.Stmt;
import typestate.TransitionFunction;

public class PredicateHandler {

	private final class AddPredicateToOtherSeed implements ResultsHandler {
		private final Statement statement;
		private final Value base;
		private final SootMethod callerMethod;
		private final EnsuredCrySLPredicate ensPred;
		private final AnalysisSeedWithSpecification secondSeed;

		private AddPredicateToOtherSeed(Statement statement, Value base, SootMethod callerMethod, EnsuredCrySLPredicate ensPred, AnalysisSeedWithSpecification secondSeed) {
			this.statement = statement;
			this.base = base;
			this.callerMethod = callerMethod;
			this.ensPred = ensPred;
			this.secondSeed = secondSeed;
		}

		@Override
		public void done(ForwardBoomerangResults<TransitionFunction> results) {
			if (results.asStatementValWeightTable().row(statement).containsKey(new Val(base, callerMethod))) {
				secondSeed.addEnsuredPredicate(ensPred);
			}
		}

		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + getOuterType().hashCode();
			result = prime * result + ((base == null) ? 0 : base.hashCode());
			result = prime * result + ((callerMethod == null) ? 0 : callerMethod.hashCode());
			result = prime * result + ((ensPred == null) ? 0 : ensPred.hashCode());
			result = prime * result + ((secondSeed == null) ? 0 : secondSeed.hashCode());
			result = prime * result + ((statement == null) ? 0 : statement.hashCode());
			return result;
		}

		@Override
		public boolean equals(Object obj) {
			if (this == obj)
				return true;
			if (obj == null)
				return false;
			if (getClass() != obj.getClass())
				return false;
			AddPredicateToOtherSeed other = (AddPredicateToOtherSeed) obj;
			if (!getOuterType().equals(other.getOuterType()))
				return false;
			if (base == null) {
				if (other.base != null)
					return false;
			} else if (!base.equals(other.base))
				return false;
			if (callerMethod == null) {
				if (other.callerMethod != null)
					return false;
			} else if (!callerMethod.equals(other.callerMethod))
				return false;
			if (ensPred == null) {
				if (other.ensPred != null)
					return false;
			} else if (!ensPred.equals(other.ensPred))
				return false;
			if (secondSeed == null) {
				if (other.secondSeed != null)
					return false;
			} else if (!secondSeed.equals(other.secondSeed))
				return false;
			if (statement == null) {
				if (other.statement != null)
					return false;
			} else if (!statement.equals(other.statement))
				return false;
			return true;
		}

		private PredicateHandler getOuterType() {
			return PredicateHandler.this;
		}

	}

	private final Table<Statement, Val, Set<EnsuredCrySLPredicate>> existingPredicates = HashBasedTable.create();
	private final Table<Statement, IAnalysisSeed, Set<EnsuredCrySLPredicate>> existingPredicatesObjectBased = HashBasedTable.create();
	private final Table<Statement, IAnalysisSeed, Set<CrySLPredicate>> expectedPredicateObjectBased = HashBasedTable.create();
	private final CryptoScanner cryptoScanner;

	public PredicateHandler(CryptoScanner cryptoScanner) {
		this.cryptoScanner = cryptoScanner;
	}

	public boolean addNewPred(IAnalysisSeed seedObj, Statement statement, Val variable, EnsuredCrySLPredicate ensPred) {
		Set<EnsuredCrySLPredicate> set = getExistingPredicates(statement, variable);
		boolean added = set.add(ensPred);
		assert existingPredicates.get(statement, variable).contains(ensPred);
		if (added) {
			onPredicateAdded(seedObj, statement, variable, ensPred);
		}
		cryptoScanner.getAnalysisListener().onSecureObjectFound(seedObj);
		Set<EnsuredCrySLPredicate> predsObjBased = existingPredicatesObjectBased.get(statement, seedObj);
		if (predsObjBased == null)
			predsObjBased = Sets.newHashSet();
		predsObjBased.add(ensPred);
		existingPredicatesObjectBased.put(statement, seedObj, predsObjBased);
		return added;
	}

	/**2
	 * @return the existingPredicates
	 */
	public Set<EnsuredCrySLPredicate> getExistingPredicates(Statement stmt, Val seed) {
		Set<EnsuredCrySLPredicate> set = existingPredicates.get(stmt, seed);
		if (set == null) {
			set = Sets.newHashSet();
			existingPredicates.put(stmt, seed, set);
		}
		return set;
	}

	private void onPredicateAdded(IAnalysisSeed seedObj, Statement statement, Val seed, EnsuredCrySLPredicate ensPred) {
		if (statement.isCallsite()) {
			InvokeExpr ivexpr = ((Stmt) statement.getUnit().get()).getInvokeExpr();
			if (ivexpr instanceof InstanceInvokeExpr) {
				InstanceInvokeExpr iie = (InstanceInvokeExpr) ivexpr;
				SootMethod method = iie.getMethod();
				SootMethod callerMethod = statement.getMethod();
				Value base = iie.getBase();
				boolean paramMatch = false;
				for (Value arg : iie.getArgs()) {
					if (seed.value() != null && seed.value().equals(arg))
						paramMatch = true;
				}
				if (paramMatch) {
					for (AnalysisSeedWithSpecification secondSeed : Lists.newArrayList(cryptoScanner.getAnalysisSeeds())) {
						secondSeed.registerResultsHandler(new AddPredicateToOtherSeed(statement, base, callerMethod, ensPred, secondSeed));

					}
				}
			}

			if (ivexpr instanceof StaticInvokeExpr && statement.getUnit().get() instanceof AssignStmt) {
				StaticInvokeExpr iie = (StaticInvokeExpr) ivexpr;
				boolean paramMatch = false;
				for (Value arg : iie.getArgs()) {
					if (seed.value() != null && seed.value().equals(arg))
						paramMatch = true;
				}
				if (paramMatch) {
					for (AnalysisSeedWithSpecification spec : Lists.newArrayList(cryptoScanner.getAnalysisSeeds())) {
						if (spec.stmt().equals(statement)) {
							spec.addEnsuredPredicate(ensPred);
						}
					}
				}
			}

		}
	}

	public void expectPredicate(IAnalysisSeed expectedOn, Statement stmt, CrySLPredicate predToBeEnsured, IAnalysisSeed expectedFrom) {
		Unit unit = stmt.getUnit().get();
		List<Unit> units = cryptoScanner.icfg().getSuccsOf(unit);
		for (Unit succ : cryptoScanner.icfg().getSuccsOf(stmt.getUnit().get())) {
			Set<CrySLPredicate> set = expectedPredicateObjectBased.get(succ, expectedOn);
			if (set == null)
				set = Sets.newHashSet();
			if(expectedFrom != null) {
				set.add(predToBeEnsured);
			}
			expectedPredicateObjectBased.put(new Statement((Stmt) succ, stmt.getMethod()), expectedOn, set);
		}
	}

	public void checkPredicates() {
		checkMissingRequiredPredicates();
		checkForContradictions();
		buildUpSubsequentErrorStack();
		cryptoScanner.getAnalysisListener().ensuredPredicates(this.existingPredicates, expectedPredicateObjectBased, computeMissingPredicates());
	}

	private void checkMissingRequiredPredicates() {
		for (AnalysisSeedWithSpecification seed : cryptoScanner.getAnalysisSeeds()) {
			Set<ISLConstraint> missingPredicates = seed.getMissingPredicates();
			for (ISLConstraint pred : missingPredicates) {
				if (pred instanceof RequiredCrySLPredicate) {
					reportMissingPred(seed, (RequiredCrySLPredicate) pred);
				} else if (pred instanceof CrySLConstraint) {
					for (CrySLPredicate altPred : ((AlternativeReqPredicate) pred).getAlternatives()) {
						// TODO create a dedicated error for alternative predicates
						// they are connected with a logical or -> the error should point that out
						reportMissingPred(seed, new RequiredCrySLPredicate(altPred, altPred.getLocation()));
					}
				}
			}
		}
	}
	
	private Map<AbstractError, Set<AbstractError>> buildUpSubsequentErrorStack() {
		Set<AbstractError> rootErrors = Sets.newHashSet();
		Map<AbstractError, Set<AbstractError>> childErrorToParentErrors = Maps.newHashMap();
		Map<Class, Integer> errorCount = new HashMap<Class, Integer>();
		int subSequentErrorsCount = 0;
		for (AnalysisSeedWithSpecification seed : cryptoScanner.getAnalysisSeeds()) {
			for (AbstractError e: seed.getErrors()) {
				Integer count = errorCount.get(e.getClass());
				if(count == null) {
					errorCount.put(e.getClass(), 1);
				} else {
					count++;
					errorCount.put(e.getClass(), count);
				}
				if(!(e instanceof RequiredPredicateError)) {
					// error has to be a root error
					rootErrors.add(e);
					childErrorToParentErrors.put(e, null);
				}
				else {
					Set<ISLConstraint> missingPredicatesWithDarkPreds = seed.getMissingPredicatesWithDarkPreds();
					RequiredPredicateError error = (RequiredPredicateError) e;
					if(missingPredicatesWithDarkPreds.contains(error.getContradictedPredicate())) {
						// error is root error, since the required predicate can also not be generated with dark preds
						rootErrors.add(e);
						childErrorToParentErrors.put(e, null);
					}
					else {
						// subsequent error
						subSequentErrorsCount++;
						
						// TODO first filter, which dark preds are used to ensure required preds
						
						// now find previous errors
						Set<IAnalysisSeed> seedsThatEnsureDarkPreds = seed.getDarkPredicates().parallelStream().map(darkPred -> darkPred.getRoot()).collect(Collectors.toSet());
		
						
						for(IAnalysisSeed parentSeedWithErrors: seedsThatEnsureDarkPreds) {
							for(AbstractError parentError: parentSeedWithErrors.getErrors()) {
								if(parentError == e) {
									continue;
								}
								Set<AbstractError> parentErrors = childErrorToParentErrors.get(parentError);
								if(parentErrors == null) {
									parentErrors = Sets.newHashSet();
								}
								parentErrors.add(e);
								childErrorToParentErrors.put(parentError, parentErrors);
							}
						}
						
						
					}
					 
					
				}
			}
		}
		String result = printSubsequentErrors(0, rootErrors, childErrorToParentErrors);
		result += getErrorStats(errorCount, subSequentErrorsCount);
		System.out.print(result);
		return childErrorToParentErrors;
	}
	
	private String getErrorStats(Map<Class, Integer> errorCount, int subSequentErrorsCount) {
		
		String result = "================================ CryptoAnalysis Summary ===================================\n";
		if(errorCount.isEmpty()) {
			result +=   "\tNo violation of any of the rules found.\n";
		}
		else {
			result +=   "\n\tCryptoAnalysis found the following violations. For details see description above.\n\n";
			for(Entry<Class, Integer> e : errorCount.entrySet()){
				result += String.format("\t%s: %s\n", e.getKey().getSimpleName(),e.getValue());
			}
			
			result +=   "\n\t" + subSequentErrorsCount + " Required Predicate Errors are subsequent (caused by other errors)";
		}
		result +=       "\n\n===========================================================================================";
		return result;
	}
	
	private String printSubsequentErrors(int level, Collection<AbstractError> errors, Map<AbstractError, Set<AbstractError>> childErrorToParentErrors) {
		if(level > 20 || errors == null) {
			return "";
		}
		String report = "";
		String tabs = "";
		for(int i=0; i<level; i++) {
			tabs += "\t";
		}
		if(level > 0) {
			report += tabs + "This error causes the following other errors: \n\n";
		}
		for(AbstractError e: errors) {
			report += getErrorString(e, tabs);
			report += printSubsequentErrors(level+2, childErrorToParentErrors.get(e), childErrorToParentErrors);
		}
		return report;
		
	}
	
	private String getErrorString(AbstractError e, String tabs) {
		String report = "";
		String className = e.getErrorLocation().getMethod().getClass().getName();
		String method = e.getErrorLocation().getMethod().getSubSignature();
		String statement = e.getErrorLocation().getUnit().get().toString();
		String errorString = e.toErrorMarkerString();
		String errorClass = e.getClass().getSimpleName();
		String errorViolatingRule = e.getRule().getClassName();
		String object = "";
		if(e instanceof ErrorWithObjectAllocation) {
			object = tabs + String.format("(on Object #%s)\n", ((ErrorWithObjectAllocation) e).getObjectLocation().getObjectId());
		}
		report += tabs + "In Class " + className + " in Method: " + method + "\n";
		report += tabs + "At statement: " + statement + "\n";
		report += tabs + String.format("%s violating CrySL rule for %s \n", errorClass, errorViolatingRule);
		report += object;
		report += tabs + errorString + "\n";
		report += "\n";
		return report;
	}

	private void reportMissingPred(AnalysisSeedWithSpecification seed, RequiredCrySLPredicate missingPred) {
		CrySLRule rule = seed.getSpec().getRule();
		if (!rule.getPredicates().parallelStream().anyMatch(e -> missingPred.getPred().getPredName().equals(e.getPredName()) && missingPred.getPred().getParameters().get(0).equals(e.getParameters().get(0)))) {
			for (CallSiteWithParamIndex v : seed.getParameterAnalysis().getAllQuerySites()) {
				if (missingPred.getPred().getInvolvedVarNames().contains(v.getVarName()) && v.stmt().equals(missingPred.getLocation())) {
					RequiredPredicateError e = new RequiredPredicateError(missingPred.getPred(), missingPred.getLocation(), seed.getSpec().getRule(), new CallSiteWithExtractedValue(v, null));
					seed.addError(e);
					cryptoScanner.getAnalysisListener().reportError(seed, e);
				}
			}
		}
	}

	private void checkForContradictions() {
		Set<Entry<CrySLPredicate, CrySLPredicate>> contradictionPairs = new HashSet<Entry<CrySLPredicate, CrySLPredicate>>();
		for (ClassSpecification c : cryptoScanner.getClassSpecifictions()) {
			CrySLRule rule = c.getRule();
			for (ISLConstraint cons : rule.getConstraints()) {
				if (cons instanceof CrySLPredicate && ((CrySLPredicate) cons).isNegated()) {
					contradictionPairs.add(new SimpleEntry<CrySLPredicate, CrySLPredicate>(rule.getPredicates().get(0), ((CrySLPredicate) cons).setNegated(false)));
				}
			}
		}
		for (Statement generatingPredicateStmt : expectedPredicateObjectBased.rowKeySet()) {
			for (Entry<Val, Set<EnsuredCrySLPredicate>> exPredCell : existingPredicates.row(generatingPredicateStmt).entrySet()) {
				Set<String> preds = new HashSet<String>();
				for (EnsuredCrySLPredicate exPred : exPredCell.getValue()) {
					preds.add(exPred.getPredicate().getPredName());
				}
				for (Entry<CrySLPredicate, CrySLPredicate> disPair : contradictionPairs) {
					if (preds.contains(disPair.getKey().getPredName()) && preds.contains(disPair.getValue().getPredName())) {
						cryptoScanner.getAnalysisListener().reportError(null, new PredicateContradictionError(generatingPredicateStmt, null, disPair));
					}
				}
			}
		}
	}

	private Table<Statement, IAnalysisSeed, Set<CrySLPredicate>> computeMissingPredicates() {
		Table<Statement, IAnalysisSeed, Set<CrySLPredicate>> res = HashBasedTable.create();
		for (Cell<Statement, IAnalysisSeed, Set<CrySLPredicate>> c : expectedPredicateObjectBased.cellSet()) {
			Set<EnsuredCrySLPredicate> exPreds = existingPredicatesObjectBased.get(c.getRowKey(), c.getColumnKey());
			if (c.getValue() == null)
				continue;
			Set<CrySLPredicate> expectedPreds = Sets.newHashSet(c.getValue());
			if (exPreds == null) {
				exPreds = Sets.newHashSet();
			}
			for (EnsuredCrySLPredicate p : exPreds) {
				expectedPreds.remove(p.getPredicate());
			}
			if (!expectedPreds.isEmpty()) {
				res.put(c.getRowKey(), c.getColumnKey(), expectedPreds);
			}
		}
		return res;
	}

}
