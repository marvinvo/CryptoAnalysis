package crypto.analysis;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.stream.Collectors;
import com.google.common.collect.HashMultimap;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.common.collect.Multimap;
import com.google.common.collect.Sets;
import com.google.common.collect.Table;
import com.google.common.collect.Table.Cell;
import boomerang.callgraph.ObservableICFG;
import boomerang.debugger.Debugger;
import boomerang.jimple.AllocVal;
import boomerang.jimple.Statement;
import boomerang.jimple.Val;
import boomerang.results.ForwardBoomerangResults;
import crypto.analysis.errors.IncompleteOperationError;
import crypto.analysis.errors.TypestateError;
import crypto.constraints.ConstraintSolver;
import crypto.constraints.ConstraintSolver.EvaluableConstraint;
import crypto.extractparameter.CallSiteWithParamIndex;
import crypto.extractparameter.ExtractParameterAnalysis;
import crypto.extractparameter.ExtractedValue;
import crypto.interfaces.ICrySLPredicateParameter;
import crypto.interfaces.ISLConstraint;
import crypto.rules.CrySLCondPredicate;
import crypto.rules.CrySLConstraint;
import crypto.rules.CrySLMethod;
import crypto.rules.CrySLObject;
import crypto.rules.CrySLPredicate;
import crypto.rules.StateNode;
import crypto.rules.TransitionEdge;
import crypto.typestate.CrySLMethodToSootMethod;
import crypto.typestate.ExtendedIDEALAnaylsis;
import crypto.typestate.ReportingErrorStateNode;
import crypto.typestate.SootBasedStateMachineGraph;
import crypto.typestate.WrappedState;
import ideal.IDEALSeedSolver;
import soot.IntType;
import soot.Local;
import soot.RefType;
import soot.SootMethod;
import soot.Type;
import soot.Unit;
import soot.Value;
import soot.ValueBox;
import soot.jimple.AssignStmt;
import soot.jimple.Constant;
import soot.jimple.IntConstant;
import soot.jimple.InvokeExpr;
import soot.jimple.Stmt;
import soot.jimple.StringConstant;
import soot.jimple.ThrowStmt;
import sync.pds.solver.nodes.Node;
import typestate.TransitionFunction;
import typestate.finiteautomata.ITransition;
import typestate.finiteautomata.State;

public class AnalysisSeedWithSpecification extends IAnalysisSeed {

	private final ClassSpecification spec;
	private ExtendedIDEALAnaylsis analysis;
	private ForwardBoomerangResults<TransitionFunction> results;
	private Collection<EnsuredCrySLPredicate> ensuredPredicates = Sets.newHashSet();
	private Collection<DarkPredicate> darkPredicates = Sets.newHashSet();
	private Collection<DarkPredicate> neededDarkPreds = null;
	private Multimap<Statement, State> typeStateChange = HashMultimap.create();
	private Collection<EnsuredCrySLPredicate> indirectlyEnsuredPredicates = Sets.newHashSet();
	private Set<ISLConstraint> missingPredicates = null;
	private Set<ISLConstraint> missingPredicatesWithDarkPreds = null;
	private ConstraintSolver constraintSolver;
	private boolean internalConstraintSatisfied;
	protected Map<Statement, SootMethod> allCallsOnObject = Maps.newLinkedHashMap();
	private ExtractParameterAnalysis parameterAnalysis;
	private Set<ResultsHandler> resultHandlers = Sets.newHashSet();
	private boolean secure = true;

	public AnalysisSeedWithSpecification(CryptoScanner cryptoScanner, Statement stmt, Val val, ClassSpecification spec) {
		super(cryptoScanner, stmt, val, spec.getFSM().getInitialWeight(stmt));
		this.spec = spec;
		this.analysis = new ExtendedIDEALAnaylsis() {

			@Override
			public SootBasedStateMachineGraph getStateMachine() {
				return spec.getFSM();
			}

			@Override
			protected ObservableICFG<Unit, SootMethod> icfg() {
				return cryptoScanner.icfg();
			}

			@Override
			protected Debugger<TransitionFunction> debugger(IDEALSeedSolver<TransitionFunction> solver) {
				return cryptoScanner.debugger(solver, AnalysisSeedWithSpecification.this);
			}

			@Override
			public CrySLResultsReporter analysisListener() {
				return cryptoScanner.getAnalysisListener();
			}
		};
	}

	@Override
	public String toString() {
		return "AnalysisSeed [" + super.toString() + " with spec " + spec.getRule().getClassName() + "]";
	}

	public void execute() {
		cryptoScanner.getAnalysisListener().seedStarted(this);
		runTypestateAnalysis(); // will create a callgraph of this seed
		if (results == null)
			// Timeout occured.
			return;
		allCallsOnObject = results.getInvokedMethodOnInstance();
		runExtractParameterAnalysis();
		checkInternalConstraints(); //check CONSTRAINTS

		Multimap<Statement, State> unitToStates = HashMultimap.create();
		for (Cell<Statement, Val, TransitionFunction> c : results.asStatementValWeightTable().cellSet()) {
			unitToStates.putAll(c.getRowKey(), getTargetStates(c.getValue()));
			for (EnsuredCrySLPredicate pred : indirectlyEnsuredPredicates) {
				// TODO only maintain indirectly ensured predicate as long as they are not
				// killed by the rule
				predicateHandler.addNewPred(this, c.getRowKey(), c.getColumnKey(), pred);
			}
		}

		computeTypestateErrorUnits();
		computeTypestateErrorsForEndOfObjectLifeTime();

		cryptoScanner.getAnalysisListener().onSeedFinished(this, results);
		cryptoScanner.getAnalysisListener().collectedValues(this, parameterAnalysis.getCollectedValues());
	}

	private void checkInternalConstraints() {
		cryptoScanner.getAnalysisListener().beforeConstraintCheck(this);
		constraintSolver = new ConstraintSolver(this, allCallsOnObject.keySet(), cryptoScanner.getAnalysisListener());
		cryptoScanner.getAnalysisListener().checkedConstraints(this, constraintSolver.getRelConstraints());
		internalConstraintSatisfied = (0 == constraintSolver.evaluateRelConstraints());
		cryptoScanner.getAnalysisListener().afterConstraintCheck(this);
	}

	private void runTypestateAnalysis() {
		analysis.run(this);
		results = analysis.getResults();
		if (results != null) {
			for (ResultsHandler handler : Lists.newArrayList(resultHandlers)) {
				handler.done(results);
			}
		}
	}

	public void registerResultsHandler(ResultsHandler handler) {
		if (results != null) {
			handler.done(results);
		} else {
			resultHandlers.add(handler);
		}
	}

	private void runExtractParameterAnalysis() {
		this.parameterAnalysis = new ExtractParameterAnalysis(this.cryptoScanner, allCallsOnObject, spec.getFSM());
		this.parameterAnalysis.run();
	}

	private void computeTypestateErrorUnits() {
		Set<Statement> allTypestateChangeStatements = Sets.newHashSet();
		for (Cell<Statement, Val, TransitionFunction> c : results.asStatementValWeightTable().cellSet()) {
			allTypestateChangeStatements.addAll(c.getValue().getLastStateChangeStatements());
		}
		for (Cell<Statement, Val, TransitionFunction> c : results.asStatementValWeightTable().cellSet()) {
			Statement curr = c.getRowKey();
			if (allTypestateChangeStatements.contains(curr)) {
				Collection<? extends State> targetStates = getTargetStates(c.getValue());
				for (State newStateAtCurr : targetStates) {
					typeStateChangeAtStatement(curr, newStateAtCurr);
				}
			}

		}
	}

	private void computeTypestateErrorsForEndOfObjectLifeTime() {
		Table<Statement, Val, TransitionFunction> endPathOfPropagation = results.getObjectDestructingStatements();

		for (Cell<Statement, Val, TransitionFunction> c : endPathOfPropagation.cellSet()) {
			Set<SootMethod> expectedMethodsToBeCalled = Sets.newHashSet();
			for (ITransition n : c.getValue().values()) {
				if (n.to() == null)
					continue;
				if (!n.to().isAccepting()) {
					if (n.to() instanceof WrappedState) {
						WrappedState wrappedState = (WrappedState) n.to();
						for (TransitionEdge t : spec.getRule().getUsagePattern().getAllTransitions()) {
							if (t.getLeft().equals(wrappedState.delegate()) && !t.from().equals(t.to())) {
								Collection<SootMethod> converted = CrySLMethodToSootMethod.v().convert(t.getLabel());
								expectedMethodsToBeCalled.addAll(converted);
							}
						}
					}
				}
			}
			if (!expectedMethodsToBeCalled.isEmpty()) {
				Statement s = c.getRowKey();
				Val val = c.getColumnKey();
				if (!(s.getUnit().get() instanceof ThrowStmt)) {
					IncompleteOperationError e = new IncompleteOperationError(s, val, getSpec().getRule(), this, expectedMethodsToBeCalled);
					this.addError(e);
					cryptoScanner.getAnalysisListener().reportError(this, e);
				}
			}
		}
	}

	private void typeStateChangeAtStatement(Statement curr, State stateNode) {
		if (typeStateChange.put(curr, stateNode)) {
			if (stateNode instanceof ReportingErrorStateNode) {
				ReportingErrorStateNode errorStateNode = (ReportingErrorStateNode) stateNode;
				TypestateError e = new TypestateError(curr, getSpec().getRule(), this, errorStateNode.getExpectedCalls());
				this.addError(e);
				cryptoScanner.getAnalysisListener().reportError(this, e);
			}
		}
		onAddedTypestateChange(curr, stateNode);
	}

	/**
	 * This method will ensure predicates on a given statement, if its state node is a predicate generating state.
	 * @param curr
	 * @param stateNode
	 */
	private void onAddedTypestateChange(Statement curr, State stateNode) {
		for (CrySLPredicate predToBeEnsured : spec.getRule().getPredicates()) {
			if (predToBeEnsured.isNegated()) {
				continue;
			}

			if (isPredicateGeneratingState(predToBeEnsured, stateNode)) {
				ensuresPred(predToBeEnsured, curr, stateNode);
			}
		}
	}

	/**
	 * Expects to ensure a predicate at a given statement and state.
	 * 
	 * If constraints of the seeds object and of the optional predicate constraint are not satisfied, 
	 * the predicate will not be generated, but expected.
	 * 
	 * @param predToBeEnsured
	 * @param currStmt
	 * @param stateNode
	 */
	private void ensuresPred(CrySLPredicate predToBeEnsured, Statement currStmt, State stateNode) {
		if (predToBeEnsured.isNegated()) {
			// By design you cannot ensure negated predicates
			return;
		}
		
		// evaluate constraints
		boolean satisfiesConstraintSytem = false;
		if(predToBeEnsured.getConstraint() != null) {
			satisfiesConstraintSytem = isPredConditionSatisfied(predToBeEnsured);
		} else {
			satisfiesConstraintSytem = isConstraintSystemSatisfied();
		}
		
		// create EnsuredPred
		EnsuredCrySLPredicate ensuredPred;
		if(satisfiesConstraintSytem) {
			ensuredPred = new EnsuredCrySLPredicate(predToBeEnsured, parameterAnalysis.getCollectedValues());
		} else {
			ensuredPred = new DarkPredicate(predToBeEnsured, parameterAnalysis.getCollectedValues(), this);
		}
		
		// check if expect predicate when *this* object is in state
		for (ICrySLPredicateParameter predicateParam : predToBeEnsured.getParameters()) {
			if (predicateParam.getName().equals("this")) {
				expectPredicateWhenThisObjectIsInState(stateNode, currStmt, ensuredPred);
			}
		}
		
		// expect predicate on *other* object
		if (currStmt.isCallsite()) {
			InvokeExpr ie = ((Stmt) currStmt.getUnit().get()).getInvokeExpr();
			SootMethod invokedMethod = ie.getMethod();
			Collection<CrySLMethod> convert = CrySLMethodToSootMethod.v().convert(invokedMethod);

			for (CrySLMethod crySLMethod : convert) {
				Entry<String, String> retObject = crySLMethod.getRetObject();
				if (!retObject.getKey().equals("_") && currStmt.getUnit().get() instanceof AssignStmt && predicateParameterEquals(predToBeEnsured.getParameters(), retObject.getKey())) {
					AssignStmt as = (AssignStmt) currStmt.getUnit().get();
					Value leftOp = as.getLeftOp();
					AllocVal val = new AllocVal(leftOp, currStmt.getMethod(), as.getRightOp(), new Statement(as, currStmt.getMethod()));
					expectPredicateOnOtherObject(currStmt, val, ensuredPred);
				}
				int i = 0;
				for (Entry<String, String> p : crySLMethod.getParameters()) {
					if (predicateParameterEquals(predToBeEnsured.getParameters(), p.getKey())) {
						Value param = ie.getArg(i);
						if (param instanceof Local) {
							Val val = new Val(param, currStmt.getMethod());
							expectPredicateOnOtherObject(currStmt, val, ensuredPred);
						}
					}
					i++;
				}

			}

		}
	}

	private boolean predicateParameterEquals(List<ICrySLPredicateParameter> parameters, String key) {
		for (ICrySLPredicateParameter predicateParam : parameters) {
			if (key.equals(predicateParam.getName())) {
				return true;
			}
		}
		return false;
	}

	/**
	 * 
	 * @param predToBeEnsured
	 * @param currStmt the statement, that expects the predicate
	 * @param accessGraph holds the type of the object
	 * @param satisfiesConstraintSytem
	 */
	private void expectPredicateOnOtherObject(Statement currStmt, Val accessGraph, EnsuredCrySLPredicate ensPred) {
		// check, if parameter is of a type with specification rules
		if (accessGraph.value() != null) {
			Type baseType = accessGraph.value().getType();
			if (baseType instanceof RefType) {
				RefType refType = (RefType) baseType;
				for (ClassSpecification spec : cryptoScanner.getClassSpecifictions()) {
					// check if refType is matching type of spec
					if (spec.getRule().getClassName().equals(refType.getSootClass().getName()) || spec.getRule().getClassName().equals(refType.getSootClass().getShortName())) {
						AnalysisSeedWithSpecification seed = cryptoScanner.getOrCreateSeedWithSpec(new AnalysisSeedWithSpecification(cryptoScanner, currStmt, accessGraph, spec));
						seed.addEnsuredPredicateFromOtherRule(ensPred);
						// we could return here, because both class specifications and parameter reference should be unique regarding their types
						return;
					}
				}
			}
		}
		// found no specification for the given parameter type
		AnalysisSeedWithEnsuredPredicate seed = cryptoScanner.getOrCreateSeed(new Node<Statement, Val>(currStmt, accessGraph));
		predicateHandler.expectPredicate(seed, currStmt, ensPred.getPredicate(), this);
		seed.addEnsuredPredicate(ensPred);
	}

	private void addEnsuredPredicateFromOtherRule(EnsuredCrySLPredicate ensuredCrySLPredicate) {
		indirectlyEnsuredPredicates.add(ensuredCrySLPredicate);
		if (results == null)
			// this seed haven't been processed yet
			return;
		for (Cell<Statement, Val, TransitionFunction> c : results.asStatementValWeightTable().cellSet()) {
			for (EnsuredCrySLPredicate pred : indirectlyEnsuredPredicates) {
				predicateHandler.addNewPred(this, c.getRowKey(), c.getColumnKey(), pred);
			}
		}
	}

	/**
	 * Expect a predicate when the seeds object is in a given state.
	 * It uses a call to the predicate handler, that stores expected predicates for each statement and variable.
	 * 
	 * When internal constraints are satisfied, the predicate will also be generated.
	 * This is done by passing a new {@EnsuredCrySLPredicate} for each {@Statement}, 
	 * that could transition to the state node and its Val, to the predicate handler.
	 * The predicate handler also stores for each statement and variable its ensured predicates.
	 * 
	 * When internal constraints are not satisfied, the predicate handler w
	 * @param stateNode
	 * @param currStmt
	 * @param predToBeEnsured
	 * @param satisfiesConstraintSytem
	 */
	private void expectPredicateWhenThisObjectIsInState(State stateNode, Statement currStmt, EnsuredCrySLPredicate ensuredPred) {
		predicateHandler.expectPredicate(this, currStmt, ensuredPred.getPredicate(), null);
		for (Cell<Statement, Val, TransitionFunction> e : results.asStatementValWeightTable().cellSet()) {
			// TODO check for any reachable state that don't kill
			// predicates.
			if (containsTargetState(e.getValue(), stateNode)) {
				predicateHandler.addNewPred(this, e.getRowKey(), e.getColumnKey(), ensuredPred);
			}
			
		}
	}

	private boolean containsTargetState(TransitionFunction value, State stateNode) {
		return getTargetStates(value).contains(stateNode);
	}

	private Collection<? extends State> getTargetStates(TransitionFunction value) {
		Set<State> res = Sets.newHashSet();
		for (ITransition t : value.values()) {
			if (t.to() != null)
				res.add(t.to());
		}
		return res;
	}

	/**
	 * This method won't cause any side effects.
	 * @return true, if internal constraints and all required predicates are satisfied.
	 */
	private boolean isConstraintSystemSatisfied() {
		if(internalConstraintSatisfied) {
			cryptoScanner.getAnalysisListener().beforePredicateCheck(this);
			boolean requiredPredicatesAreEnsured = fastCheckRequiredPredicates(this.ensuredPredicates);
			cryptoScanner.getAnalysisListener().afterPredicateCheck(this);
			return requiredPredicatesAreEnsured;
		}
		return false;
	}
	
	private Set<ISLConstraint> getRequiredPredicates(){
		// get the required predicates and remove all predefined predicates, because they have dedicated errors
		Set<ISLConstraint> requiredPredicates = Sets.newHashSet(constraintSolver.getRequiredPredicates());
		requiredPredicates.removeAll(requiredPredicates.parallelStream()
				.filter(p -> (p instanceof RequiredCrySLPredicate && ConstraintSolver.predefinedPreds.contains(((RequiredCrySLPredicate) p).getPred().getPredName()))
				|| (p instanceof AlternativeReqPredicate && ConstraintSolver.predefinedPreds.contains(((AlternativeReqPredicate) p).getAlternatives().get(0).getPredName()))).collect(Collectors.toList()));
		return requiredPredicates;
	}
	
	/**
	 * This method will efficiently check if all required predicates are satisfied.
	 * It won't cause any side effects.
	 * @return
	 */
	private boolean fastCheckRequiredPredicates(Collection<EnsuredCrySLPredicate> existingPredicates) {
		return this.getRequiredPredicates().parallelStream().allMatch(p -> fastCheckRequiredPredicate(p, existingPredicates));
	}
	
	/**
	 * This method will efficiently check if a required predicates is satisfied.
	 * This method is used in @fastCheckRequiredPredicates and in @evaluatePredCond
	 * @param pred
	 * @param existingPredicates
	 * @return
	 */
	private boolean fastCheckRequiredPredicate(ISLConstraint pred, Collection<EnsuredCrySLPredicate> existingPredicates) {
		if (pred instanceof RequiredCrySLPredicate) {
			RequiredCrySLPredicate reqPred = (RequiredCrySLPredicate) pred;
			if(reqPred.getPred().isNegated()){
				if(existingPredicates.parallelStream().anyMatch(ensPred -> ensPred.getPredicate().equals(reqPred.getPred()) && doPredsParametersMatch(reqPred.getPred(), ensPred))) {
					// predicate is ensured, but is required to be not ensured
					if(isPredConditionSatisfied(reqPred.getPred())) {
						// also condition is satisfied
						return false;
					}
				}
			}
			else {
				if(!existingPredicates.parallelStream().anyMatch(ensPred -> ensPred.getPredicate().equals(reqPred.getPred()) && doPredsParametersMatch(reqPred.getPred(), ensPred))) {
					// predicate is not ensured, but is required to be ensured
					if(isPredConditionSatisfied(reqPred.getPred())) {
						// also condition is satisfied
						return false;
					}
				}
			}
		} else {
			List<CrySLPredicate> alternatives = ((AlternativeReqPredicate) pred).getAlternatives();
			List<CrySLPredicate> negatives = alternatives.parallelStream().filter(e -> e.isNegated()).collect(Collectors.toList()); // holds all negated alternative preds
		
			// TODO check if it is faster to first check positives and then negatives
			if (negatives.isEmpty() || negatives.parallelStream().allMatch(e -> 
				existingPredicates.parallelStream().anyMatch(ensPred -> ensPred.getPredicate().equals(e) && doPredsParametersMatch(e, ensPred)))) {
				// all negative alternative preds are ensured
				alternatives.removeAll(negatives); // now check the positives
				if (!alternatives.parallelStream().anyMatch(e -> 
				existingPredicates.parallelStream().anyMatch(ensPred -> ensPred.getPredicate().equals(e) && doPredsParametersMatch(e, ensPred)))) {
					// also no positiv alternative pred is ensured
					if(alternatives.parallelStream().allMatch(p -> isPredConditionSatisfied(p))) {
						// also all conditions are all true
						return false;
					}
				}
			}		
		}
		// passed all checks!
		return true;
	}

	/**
	 * This method will cause side effects on @missingPredicates, @missingPredicatesWithDarkPreds and @usedDarkPreds .
	 * It will store predicates in these lists.
	 * @param existingEnsuredPredicates
	 * @param existingDarkPredicates
	 */
	private void computeRemainingRequiredPredicates(Collection<EnsuredCrySLPredicate> existingEnsuredPredicates, Collection<DarkPredicate> existingDarkPredicates) {
		Set<ISLConstraint> requiredPredicates = getRequiredPredicates();
		Set<ISLConstraint> remainingRequiredPredicates = Sets.newHashSet();
		Set<ISLConstraint> remainingRequiredPredicatesWithDarkPreds = Sets.newHashSet();
		Set<DarkPredicate> usedDarkPredicates = Sets.newHashSet();
		
		for(ISLConstraint pred: requiredPredicates) {
			if (pred instanceof RequiredCrySLPredicate) {
				RequiredCrySLPredicate reqPred = (RequiredCrySLPredicate) pred;
				if(isPredConditionSatisfied(reqPred.getPred())) {
					// condition is satisfied, hence the pred has to be satisfied too
					if(reqPred.getPred().isNegated()){
						if(existingEnsuredPredicates.parallelStream().anyMatch(ensPred -> ensPred.getPredicate().equals(reqPred.getPred()) && doPredsParametersMatch(reqPred.getPred(), ensPred))) {
							// predicate is ensured, but is required to be not ensured
							remainingRequiredPredicates.add(reqPred);
						}
					}
					else {
						if(!existingEnsuredPredicates.parallelStream().anyMatch(ensPred -> ensPred.getPredicate().equals(reqPred.getPred()) && doPredsParametersMatch(reqPred.getPred(), ensPred))) {
							// predicate is not ensured, but is required to be ensured
							remainingRequiredPredicates.add(reqPred);
							// now check, if a dark predicate is ensuring the pred
							Collection<DarkPredicate> darkPredsThatEnsureRequiredPred = existingDarkPredicates.parallelStream().filter(darkPred -> darkPred.getPredicate().equals(reqPred.getPred()) && doPredsParametersMatch(reqPred.getPred(), darkPred)).collect(Collectors.toList());
							if(darkPredsThatEnsureRequiredPred.isEmpty()) {
								// found no matching dark pred
								remainingRequiredPredicatesWithDarkPreds.add(reqPred);
							}
							else {
								usedDarkPredicates.addAll(darkPredsThatEnsureRequiredPred);
							}
						}
					}
				}
			} else {
				List<CrySLPredicate> alternatives = ((AlternativeReqPredicate) pred).getAlternatives();
				List<CrySLPredicate> negatives = alternatives.parallelStream().filter(e -> e.isNegated()).collect(Collectors.toList()); // holds all negated alternative preds
			
				if(alternatives.parallelStream().allMatch(p -> isPredConditionSatisfied(p))) {
					// all conditions are satisfied
					// TODO check if it is faster to first check positives and then negatives
					if (!alternatives.isEmpty() && (negatives.isEmpty() || negatives.parallelStream().allMatch(e -> 
						existingEnsuredPredicates.parallelStream().anyMatch(ensPred -> ensPred.getPredicate().equals(e) && doPredsParametersMatch(e, ensPred))))) {
						// all negative alternative preds are ensured
						alternatives.removeAll(negatives); // now check the positives
						if (alternatives.isEmpty() || !alternatives.parallelStream().anyMatch(e -> 
						existingEnsuredPredicates.parallelStream().anyMatch(ensPred -> ensPred.getPredicate().equals(e) && doPredsParametersMatch(e, ensPred)))) {
							// also no positiv alternative pred is ensured
							// hence the alternative pred is not ensured
							remainingRequiredPredicates.add(pred);
							// now check if any alternative preds are ensured with dark preds
							// this can only be the case for positiv preds
							Collection<DarkPredicate> darkPredsThatEnsureAnyPositiveAlternativePred = existingDarkPredicates.parallelStream().filter(darkPred -> alternatives.parallelStream().anyMatch(reqPred -> darkPred.getPredicate().equals(reqPred) && doPredsParametersMatch(reqPred, darkPred))).collect(Collectors.toList());
							if(darkPredsThatEnsureAnyPositiveAlternativePred.isEmpty()) {
								// found no matching dark pred
								remainingRequiredPredicatesWithDarkPreds.addAll(alternatives);
							}
							else {
								usedDarkPredicates.addAll(darkPredsThatEnsureAnyPositiveAlternativePred);
							}
						}
					}
				}
			}
		}
		this.missingPredicates = remainingRequiredPredicates;
		this.missingPredicatesWithDarkPreds = remainingRequiredPredicatesWithDarkPreds;
		this.neededDarkPreds = usedDarkPredicates;
	}
	
	public Collection<ISLConstraint> getMissingPredicates(){
		if(this.missingPredicates == null) {
			// this is ok, because the method is called after all analysis are finished.
			computeRemainingRequiredPredicates(this.ensuredPredicates, this.darkPredicates);
		}
		return this.missingPredicates;
	}
	
	public Collection<ISLConstraint> getMissingPredicatesWithDarkPreds(){
		if(this.missingPredicatesWithDarkPreds == null) {
			// this is ok, because the method is called after all analysis are finished.
			computeRemainingRequiredPredicates(this.ensuredPredicates, this.darkPredicates);
		}
		return this.missingPredicatesWithDarkPreds;
	}
	
	public Collection<DarkPredicate> getNeededDarkPreds(){
		if(this.neededDarkPreds == null) {
			// this is ok, because the method is called after all analysis are finished.
			computeRemainingRequiredPredicates(this.ensuredPredicates, this.darkPredicates);
		}
		return this.neededDarkPreds;
	}
	
	private boolean isPredConditionSatisfied(CrySLPredicate pred) {
		final ISLConstraint conditional = pred.getConstraint();
		if (conditional == null) {
			return true;
		}
		//condition could be a constraint or a pred
		if(conditional instanceof CrySLPredicate && !ConstraintSolver.predefinedPreds.contains(((CrySLPredicate) conditional).getPredName())) {
			return fastCheckRequiredPredicate(new RequiredCrySLPredicate((CrySLPredicate)conditional, null), this.ensuredPredicates);
		}
		else {
			EvaluableConstraint evalCons = constraintSolver.createConstraint(conditional);
			evalCons.evaluate();
			if (evalCons.hasErrors()) {
				return false;
			}
			return true;
		}
	}

	private boolean doPredsParametersMatch(CrySLPredicate pred, EnsuredCrySLPredicate ensPred) {
		boolean requiredPredicatesExist = true;
		for (int i = 0; i < pred.getParameters().size(); i++) {
			String var = pred.getParameters().get(i).getName();
			if (isOfNonTrackableType(var)) {
				continue;
			} else if (pred.getInvolvedVarNames().contains(var)) {

				final String parameterI = ensPred.getPredicate().getParameters().get(i).getName();
				Collection<String> actVals = Collections.emptySet();
				Collection<String> expVals = Collections.emptySet();

				for (CallSiteWithParamIndex cswpi : ensPred.getParametersToValues().keySet()) {
					if (cswpi.getVarName().equals(parameterI)) {
						actVals = retrieveValueFromUnit(cswpi, ensPred.getParametersToValues().get(cswpi));
					}
				}
				for (CallSiteWithParamIndex cswpi : parameterAnalysis.getCollectedValues().keySet()) {
					if (cswpi.getVarName().equals(var)) {
						expVals = retrieveValueFromUnit(cswpi, parameterAnalysis.getCollectedValues().get(cswpi));
					}
				}

				String splitter = "";
				int index = -1;
				if (pred.getParameters().get(i) instanceof CrySLObject) {
					CrySLObject obj = (CrySLObject) pred.getParameters().get(i);
					if (obj.getSplitter() != null) {
						splitter = obj.getSplitter().getSplitter();
						index = obj.getSplitter().getIndex();
					}
				}
				for (String foundVal : expVals) {
					if (index > -1) {
						foundVal = foundVal.split(splitter)[index];
					}
					actVals = actVals.parallelStream().map(e -> e.toLowerCase()).collect(Collectors.toList());
					requiredPredicatesExist &= actVals.contains(foundVal.toLowerCase());
				}
			} else {
				requiredPredicatesExist = false;
			}
		}
		return requiredPredicatesExist;
	}

	private Collection<String> retrieveValueFromUnit(CallSiteWithParamIndex cswpi, Collection<ExtractedValue> collection) {
		Collection<String> values = new ArrayList<String>();
		for (ExtractedValue q : collection) {
			Unit u = q.stmt().getUnit().get();
			if (cswpi.stmt().equals(q.stmt())) {
				if (u instanceof AssignStmt) {
					values.add(retrieveConstantFromValue(((AssignStmt) u).getRightOp().getUseBoxes().get(cswpi.getIndex()).getValue()));
				} else {
					values.add(retrieveConstantFromValue(u.getUseBoxes().get(cswpi.getIndex()).getValue()));
				}
			} else if (u instanceof AssignStmt) {
				final Value rightSide = ((AssignStmt) u).getRightOp();
				if (rightSide instanceof Constant) {
					values.add(retrieveConstantFromValue(rightSide));
				} else {
					final List<ValueBox> useBoxes = rightSide.getUseBoxes();

					// varVal.put(callSite.getVarName(),
					// retrieveConstantFromValue(useBoxes.get(callSite.getIndex()).getValue()));
				}
			}
			// if (u instanceof AssignStmt) {
			// final List<ValueBox> useBoxes = ((AssignStmt) u).getRightOp().getUseBoxes();
			// if (!(useBoxes.size() <= cswpi.getIndex())) {
			// values.add(retrieveConstantFromValue(useBoxes.get(cswpi.getIndex()).getValue()));
			// }
			// } else if (cswpi.getStmt().equals(u)) {
			// values.add(retrieveConstantFromValue(cswpi.getStmt().getUseBoxes().get(cswpi.getIndex()).getValue()));
			// }
		}
		return values;
	}

	private String retrieveConstantFromValue(Value val) {
		if (val instanceof StringConstant) {
			return ((StringConstant) val).value;
		} else if (val instanceof IntConstant || val.getType() instanceof IntType) {
			return val.toString();
		} else {
			return "";
		}
	}

	private final static List<String> trackedTypes = Arrays.asList("java.lang.String", "int", "java.lang.Integer");

	private boolean isOfNonTrackableType(String varName) {
		for (Entry<String, String> object : spec.getRule().getObjects()) {
			if (object.getValue().equals(varName) && trackedTypes.contains(object.getKey())) {
				return false;
			}
		}
		return true;
	}

	public ClassSpecification getSpec() {
		return spec;
	}

	public void addEnsuredPredicate(EnsuredCrySLPredicate ensPred) {
		if((ensPred instanceof DarkPredicate && darkPredicates.add((DarkPredicate) ensPred))){
			// do nothing
		}
		else if(!(ensPred instanceof DarkPredicate) && ensuredPredicates.add(ensPred)) {
			// ensPred was added to ensuredPredicates
			for (Entry<Statement, State> e : typeStateChange.entries())
				onAddedTypestateChange(e.getKey(), e.getValue());
		}
	}

	/**
	 * Returns true, if the predicate is generated in the state.
	 * @param ensPred
	 * @param stateNode
	 * @return
	 */
	private boolean isPredicateGeneratingState(CrySLPredicate ensPred, State stateNode) {
		return ensPred instanceof CrySLCondPredicate && isConditionalState(((CrySLCondPredicate) ensPred).getConditionalMethods(), stateNode) || (!(ensPred instanceof CrySLCondPredicate) && stateNode.isAccepting());
	}

	private boolean isConditionalState(Set<StateNode> conditionalMethods, State state) {
		if (conditionalMethods == null)
			return false;
		for (StateNode s : conditionalMethods) {
			if (new WrappedState(s).equals(state)) {
				return true;
			}
		}
		return false;
	}

	public ExtractParameterAnalysis getParameterAnalysis() {
		return parameterAnalysis;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + ((spec == null) ? 0 : spec.hashCode());
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
		AnalysisSeedWithSpecification other = (AnalysisSeedWithSpecification) obj;
		if (spec == null) {
			if (other.spec != null)
				return false;
		} else if (!spec.equals(other.spec))
			return false;
		return true;
	}

	public boolean isSecure() {
		return secure;
	}

	public void setSecure(boolean secure) {
		this.secure = secure;
	}

	@Override
	public Set<Node<Statement, Val>> getDataFlowPath() {
		return results.getDataFlowPath();
	}

	public Map<Statement, SootMethod> getAllCallsOnObject() {
		return allCallsOnObject;
	}

}
