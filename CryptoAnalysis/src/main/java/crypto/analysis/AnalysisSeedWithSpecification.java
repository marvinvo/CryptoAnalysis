package crypto.analysis;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
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
import crypto.analysis.errors.AbstractError;
import crypto.analysis.errors.IncompleteOperationError;
import crypto.analysis.errors.RequiredPredicateError;
import crypto.analysis.errors.TypestateError;
import crypto.constraints.ConstraintSolver;
import crypto.constraints.ConstraintSolver.EvaluableConstraint;
import crypto.extractparameter.CallSiteWithExtractedValue;
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
import soot.UnitBox;
import soot.Value;
import soot.ValueBox;
import soot.jimple.AssignStmt;
import soot.jimple.Constant;
import soot.jimple.IntConstant;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;
import soot.jimple.Stmt;
import soot.jimple.StringConstant;
import soot.jimple.ThrowStmt;
import soot.jimple.internal.JAssignStmt;
import soot.jimple.internal.JInvokeStmt;
import soot.jimple.internal.JimpleLocal;
import sync.pds.solver.nodes.Node;
import typestate.TransitionFunction;
import typestate.finiteautomata.ITransition;
import typestate.finiteautomata.State;

public class AnalysisSeedWithSpecification extends IAnalysisSeed {

	// general
	private final ClassSpecification spec;
	private boolean secure = true;
	// typestate
	private ExtendedIDEALAnaylsis analysis;
	private ForwardBoomerangResults<TransitionFunction> results;
	protected Map<Statement, SootMethod> allCallsOnObject = Maps.newLinkedHashMap();
	private Set<ResultsHandler> resultHandlers = Sets.newHashSet();
	private Multimap<Statement, State> typeStateChange = HashMultimap.create();
	private ExtractParameterAnalysis parameterAnalysis;
	// constraints
	private ConstraintSolver constraintSolver;
	private boolean internalConstraintSatisfied;
	// predicates
	private Collection<EnsuredCrySLPredicate> ensuredPredicates = Sets.newHashSet();
	private Collection<DarkPredicate> darkPredicates = Sets.newHashSet();
	private Collection<DarkPredicate> neededDarkPreds = null;
	private Set<ISLConstraint> missingPredicates = null;
	private Set<ISLConstraint> missingPredicatesWithDarkPreds = null;
	private Collection<EnsuredCrySLPredicate> indirectlyEnsuredPredicates = Sets.newHashSet(); //TODO: check if this still has an usage

	/**
	 * Constructor
	 */
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

	/**
	 * This will process the seed, check all constraints and add errors.
	 */
	public void execute() {
		cryptoScanner.getAnalysisListener().seedStarted(this);
		
		this.results = runTypestateAnalysis(); // creates a callgraph of this seed
		if (results == null)
			return; // Timeout occured.
		this.allCallsOnObject = results.getInvokedMethodOnInstance(); // get all statements are calls on this seeds object 
		this.parameterAnalysis = runExtractParameterAnalysis(allCallsOnObject); // extract parameters, that are used in statements of allCallsOnObject
		this.internalConstraintSatisfied = checkInternalConstraints(); //check CONSTRAINTS

		// TODO documentation
		Multimap<Statement, State> unitToStates = HashMultimap.create();
		for (Cell<Statement, Val, TransitionFunction> c : results.asStatementValWeightTable().cellSet()) {
			unitToStates.putAll(c.getRowKey(), getTargetStates(c.getValue()));
			for (EnsuredCrySLPredicate pred : indirectlyEnsuredPredicates) {
				// TODO only maintain indirectly ensured predicate as long as they are not
				// killed by the rule
				predicateHandler.addNewPred(this, c.getRowKey(), c.getColumnKey(), pred);
				// TODO: this should be done better
				// create dublicated version for this parameter
				pred.addAnalysisSeedToParameter(this, 0);
				this.addEnsuredPredicate(pred);
				/*
				if(pred.getPredicate().getParameters().stream().anyMatch(p -> p instanceof CrySLObject && ((CrySLObject)p).getJavaType().equals(this.spec.toString()))) {
					EnsuredCrySLPredicate dublicate;
					List<ICrySLPredicateParameter> params = pred.getPredicate().getParameters().stream().map(p -> p instanceof CrySLObject && ((CrySLObject)p).getJavaType().equals(this.spec.toString()) ? new CrySLObject("this", "null") : p).collect(Collectors.toList());
			
					if(pred instanceof DarkPredicate) {
						dublicate = new DarkPredicate(new CrySLPredicate(params.get(0), pred.getPredicate().getPredName(), params, false), pred.getParametersToValues(), ((DarkPredicate) pred).getRoot());
					}
					else {
						dublicate = new EnsuredCrySLPredicate(new CrySLPredicate(params.get(0), pred.getPredicate().getPredName(), params, false), pred.getParametersToValues());
					}
					this.addEnsuredPredicate(dublicate);
				}*/
			}
		}
		
		computeTypestateErrorUnits();
		computeTypestateErrorsForEndOfObjectLifeTime();
		
		checkConstraintsAndEnsurePredicates();

		cryptoScanner.getAnalysisListener().onSeedFinished(this, results);
		cryptoScanner.getAnalysisListener().collectedValues(this, parameterAnalysis.getCollectedValues());
	}

	
	//
	//
	// TYPESTATE CHECKS
	//
	//

	private ForwardBoomerangResults<TransitionFunction> runTypestateAnalysis() {
		analysis.run(this);
		results = analysis.getResults();
		if (results != null) {
			for (ResultsHandler handler : Lists.newArrayList(resultHandlers)) {
				handler.done(results);
			}
		}
		return results;
	}

	public void registerResultsHandler(ResultsHandler handler) {
		if (results != null) {
			handler.done(results);
		} else {
			resultHandlers.add(handler);
		}
	}

	private ExtractParameterAnalysis runExtractParameterAnalysis(Map<Statement, SootMethod> allCallsOnObject) {
		ExtractParameterAnalysis parameterAnalysis = new ExtractParameterAnalysis(this.cryptoScanner, allCallsOnObject, spec.getFSM());
		parameterAnalysis.run();
		return parameterAnalysis;
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
					addAndCheckTypeStateChangeAtStatement(curr, newStateAtCurr);
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

	/**
	 * This method will cause side effects on {@attribute typeStateChange} by adding a new entry for curr and stateNode.
	 * Further, it reports {@link TypestateError}s and call @onAddedTypestateChange method to generate potential predicates.
	 * @param curr
	 * @param stateNode
	 */
	private void addAndCheckTypeStateChangeAtStatement(Statement curr, State stateNode) {
		if (typeStateChange.put(curr, stateNode)) {
			if (stateNode instanceof ReportingErrorStateNode) {
				ReportingErrorStateNode errorStateNode = (ReportingErrorStateNode) stateNode;
				TypestateError e = new TypestateError(curr, getSpec().getRule(), this, errorStateNode.getExpectedCalls());
				this.addError(e);
				cryptoScanner.getAnalysisListener().reportError(this, e);
			}
		}
	}
	
	
	//
	//
	// PREDICATE MECHANISM
	//
	//
	
	/**
	 * This is used to add a new ensured predicate and re-run all constraint and predicate checks to see, 
	 * if new predicates should be ensured.
	 * @param ensPred
	 */
	public void addEnsuredPredicate(EnsuredCrySLPredicate ensPred) {
		if((ensPred instanceof DarkPredicate && darkPredicates.add((DarkPredicate) ensPred))){
			// do nothing
		}
		else if(!(ensPred instanceof DarkPredicate) && ensuredPredicates.add(ensPred)) {
			// ensPred was added to ensuredPredicates
			checkConstraintsAndEnsurePredicates();
		}
	}
	
	/**
	 * This method will trigger the whole predicate mechanism.
	 * It creates an ensured or dark predicate, based on constraints (CONSTRAINTS and REQUIRES) or predicate condition (condition => predToBeEnsured)
	 * for each typestate change entry, if that predicate should be generated after transition of that typestate change.
	 */
	private void checkConstraintsAndEnsurePredicates() {
		// evaluate constraints (CONSTRAINTS and REQUIRES)
		boolean satisfiesConstraintSytem = isConstraintSystemSatisfied();
				
		for (CrySLPredicate predToBeEnsured : spec.getRule().getPredicates()) {
			if (predToBeEnsured.isNegated()) {
				// you cannot ensure negated predicates by design
				continue;
			}
			for (Entry<Statement, State> e : typeStateChange.entries()) {
				if (isPredicateGeneratingState(predToBeEnsured, e.getValue())) {
					// this is a potential location, where the predicate should be ensured on satisfied constraints
					
					// Create an ensured pred.
					// Based on constraints or predicate condition, this will be either an EnsuredCrySLPredicate or DarkPredicate. 
					EnsuredCrySLPredicate ensuredPred;
					if(satisfiesConstraintSytem && isPredConditionSatisfied(predToBeEnsured))
					{ 
						ensuredPred = new EnsuredCrySLPredicate(predToBeEnsured, parameterAnalysis.getCollectedValues());
					} else {
						ensuredPred = new DarkPredicate(predToBeEnsured, parameterAnalysis.getCollectedValues(), this);
					}
					ensuresPred(ensuredPred, e.getKey(), e.getValue());
				}
			}
		}
	}

	/**
	 * This will either ensure a {@link DarkPredicate} or an {@link EnsuredCrySLPredicate}, depending on the satisfaction of this seeds constraints.
	 * If constraints (in ORDER, CONSTRAINTS and REQUIRES) are not satisfied, a {@link DarkPredicate} is ensured, else an {@link EnsuredCrySLPredicate}.
	 * 
	 * This method is called by @onAddedTypestateChange.
	 * 
	 * @param predToBeEnsured 
	 * @param currStmt a statement before state change
	 * @param stateNode the next state, after execution of {@param currStmt}
	 */
	private void ensuresPred(EnsuredCrySLPredicate ensuredPred, Statement currStmt, State stateNode) {
		if (ensuredPred.getPredicate().isNegated()) {
			return; // By design you cannot ensure negated predicates
		}
		
		// check if expect predicate when *this* object is in state
		// by design, this can only be the first parameter
		if(ensuredPred.getPredicate().getParameters().get(0).getName().equals("this")){
			ensuredPred.addAnalysisSeedToParameter(this, 0);
			expectPredicateWhenThisObjectIsInState(stateNode, currStmt, ensuredPred);
		}
		
		// expect predicate on *other* object
		if (currStmt.isCallsite()) {
			InvokeExpr ie = ((Stmt) currStmt.getUnit().get()).getInvokeExpr();
			SootMethod invokedMethod = ie.getMethod();
			Collection<CrySLMethod> convert = CrySLMethodToSootMethod.v().convert(invokedMethod);

			for (CrySLMethod crySLMethod : convert) {
				Entry<String, String> retObject = crySLMethod.getRetObject();
				if (!retObject.getKey().equals("_") && 
						currStmt.getUnit().get() instanceof AssignStmt) {
					int matchPosition = predicateParameterEquals(ensuredPred.getPredicate().getParameters(), retObject.getKey());
					if(matchPosition >= 0) {
						AssignStmt as = (AssignStmt) currStmt.getUnit().get();
						Value leftOp = as.getLeftOp();
						AllocVal val = new AllocVal(leftOp, currStmt.getMethod(), as.getRightOp(), new Statement(as, currStmt.getMethod()));
						// TODO check
						expectPredicateOnOtherObject(currStmt, val, ensuredPred, matchPosition);
					}
				}
				int i = 0;
				for (Entry<String, String> p : crySLMethod.getParameters()) {
					int matchPosition = predicateParameterEquals(ensuredPred.getPredicate().getParameters(), p.getKey());
					if (matchPosition >= 0) {
						Value param = ie.getArg(i);
						if (param instanceof Local) {
							Val val = new Val(param, currStmt.getMethod());
							expectPredicateOnOtherObject(currStmt, val, ensuredPred, matchPosition);
						}
					}
					i++;
				}

			}

		}
	}

	/**
	 * @param parameters predicates parameter list
	 * @param key parameter name that should be contained
	 * @return true, if {@param key} is contained in {@param parameters} 
	 */
	private int predicateParameterEquals(List<ICrySLPredicateParameter> parameters, String key) {
		for(int i=0; i<parameters.size(); i++) {
			ICrySLPredicateParameter predicateParam = parameters.get(i);
			if (key.equals(predicateParam.getName())) {
				return i;
			}
		}
		return -1;
	}

	/**
	 * This method is called, whenever this seed ensures a predicate that contains other seeds in its parameter list.
	 * 
	 * @param currStmt statement, that ensures the predicate
	 * @param accessGraph holds the type of the other seeds object
	 * @param ensPred Can be either a DarkPredicate or an EnsuredCrySLPredicate, depending on the satisfaction of this seeds constraints.
	 */
	private void expectPredicateOnOtherObject(Statement currStmt, Val accessGraph, EnsuredCrySLPredicate ensPred, int positionOfOtherObject) {
		// TODO: Refactor
		boolean matched = false;
		// check, if parameter is of a type with specification rules
		if (accessGraph.value() != null) {
			Type baseType = accessGraph.value().getType();
			if (baseType instanceof RefType) {
				RefType refType = (RefType) baseType;
				for (ClassSpecification spec : cryptoScanner.getClassSpecifictions()) {
					// check if refType is matching type of spec
					if (spec.getRule().getClassName().equals(refType.getSootClass().getName()) || spec.getRule().getClassName().equals(refType.getSootClass().getShortName())) {
						AnalysisSeedWithSpecification seed = cryptoScanner.getOrCreateSeedWithSpec(new AnalysisSeedWithSpecification(cryptoScanner, currStmt, accessGraph, spec));
						ensPred.addAnalysisSeedToParameter(seed, positionOfOtherObject);
						seed.addEnsuredPredicateFromOtherRule(ensPred);
						// we could return here, because both class specifications and parameter reference should be unique regarding their types
						if(!(ensPred instanceof DarkPredicate)) {
							matched = true;
						}
					}
				}
			}
		}
		if(!matched) {
			// found no specification for the given parameter type
			AnalysisSeedWithEnsuredPredicate seed = cryptoScanner.getOrCreateSeed(new Node<Statement, Val>(currStmt, accessGraph));
			ensPred.addAnalysisSeedToParameter(seed, positionOfOtherObject);
			predicateHandler.expectPredicate(seed, currStmt, ensPred.getPredicate());
			seed.addEnsuredPredicate(ensPred);
		}
		
	}

	/**
	 * This method is called by other seeds, whenever they ensure a predicate that contains this seed in its parameter list.
	 * In instance, this method is triggered by the @expectPredicateOnOtherObject.
	 *
	 * @param ensuredCrySLPredicate Can be either a DarkPredicate or an EnsuredCrySLPredicate, depending on the satisfaction of this seeds constraints.
	 */
	private void addEnsuredPredicateFromOtherRule(EnsuredCrySLPredicate ensuredCrySLPredicate) {
		indirectlyEnsuredPredicates.add(ensuredCrySLPredicate);
		
		// TODO: this should be done better
		// create dublicated version for "this" parameter.
		// this has to be done since required predicates could also hold "this" as a parameter.
		ensuredCrySLPredicate.addAnalysisSeedToParameter(this, 0);
		this.addEnsuredPredicate(ensuredCrySLPredicate);
		/*
		if(ensuredCrySLPredicate.getPredicate().getParameters().stream().anyMatch(p -> p instanceof CrySLObject && ((CrySLObject)p).getJavaType().equals(this.spec.toString()))) {
			EnsuredCrySLPredicate dublicate;
			List<ICrySLPredicateParameter> params = ensuredCrySLPredicate.getPredicate().getParameters().stream().map(p -> p instanceof CrySLObject && ((CrySLObject)p).getJavaType().equals(this.spec.toString()) ? new CrySLObject("this", "null") : p).collect(Collectors.toList());
	
			if(ensuredCrySLPredicate instanceof DarkPredicate) {
				dublicate = new DarkPredicate(new CrySLPredicate(params.get(0), ensuredCrySLPredicate.getPredicate().getPredName(), params, false), ensuredCrySLPredicate.getParametersToValues(), ((DarkPredicate) ensuredCrySLPredicate).getRoot());
			}
			else {
				dublicate = new EnsuredCrySLPredicate(new CrySLPredicate(params.get(0), ensuredCrySLPredicate.getPredicate().getPredName(), params, false), ensuredCrySLPredicate.getParametersToValues());
			}
			ensuredCrySLPredicate = dublicate;
			this.addEnsuredPredicate(dublicate);
		}*/
		
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
	 * This method is called, when the seed expects to ensure a predicate on a statement after a transition to a specific state.
	 * After this method was called, the {@param predToBeEnsured} is passed to the {@link PredicateHandler} 
	 * with each statement of all calls on this seed, which could transition to the specific state.
	 * 
	 * In crysl, these predicates contains "this" as a parameter and are accommodated in the ENSURES section.
	 * Further, the state will be declared with the keyword "after".
	 * If no state was declared, the final state (or end of lifetime state) is going to be passed.
	 * @param stateNode 
	 * @param currStmt 
	 * @param predToBeEnsured Can be either a DarkPredicate or an EnsuredCrySLPredicate, depending on the satisfaction of this seeds constraints.
	 */
	private void expectPredicateWhenThisObjectIsInState(State stateNode, Statement currStmt, EnsuredCrySLPredicate ensuredPred) {
		predicateHandler.expectPredicate(this, currStmt, ensuredPred.getPredicate());
		for (Cell<Statement, Val, TransitionFunction> e : results.asStatementValWeightTable().cellSet()) {
			// TODO check for any reachable state that don't kill
			// predicates.
			if (containsTargetState(e.getValue(), stateNode)) {
				predicateHandler.addNewPred(this, e.getRowKey(), e.getColumnKey(), ensuredPred);
			}
		}
	}

	/**
	 * @param value
	 * @param stateNode
	 * @return true, if the {@link TransitionFunction} have a transition to the {@link State} stateNode.
	 */
	private boolean containsTargetState(TransitionFunction value, State stateNode) {
		return getTargetStates(value).contains(stateNode);
	}

	/** 
	 * @param value
	 * @return all {@link State}'s, that are reachable with the {@link TransitionFunction} value.
	 */
	private Collection<? extends State> getTargetStates(TransitionFunction value) {
		Set<State> res = Sets.newHashSet();
		for (ITransition t : value.values()) {
			if (t.to() != null)
				res.add(t.to());
		}
		return res;
	}

	
	//
	//
	// CONSTRAINTS CHECK
	//
	//
	
	/**
	 * This method will evaluate constraints in CONSTRAINT section.
	 * @return true, if constraints are satisfied
	 */
	private boolean checkInternalConstraints() {
		cryptoScanner.getAnalysisListener().beforeConstraintCheck(this);
		constraintSolver = new ConstraintSolver(this, allCallsOnObject.keySet(), cryptoScanner.getAnalysisListener());
		cryptoScanner.getAnalysisListener().checkedConstraints(this, constraintSolver.getRelConstraints());
		boolean constraintSatisfied = (0 == constraintSolver.evaluateRelConstraints());
		cryptoScanner.getAnalysisListener().afterConstraintCheck(this);
		return constraintSatisfied;
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
	
	/**
	 * This method will receive all required predicates from {@link ConstraintSolver} 
	 * and filter out predicates that are predefined, because they are validated by the {@link ConstraintSolver} itself.
	 * @return required predicates for seed object
	 */
	private Set<ISLConstraint> getRequiredPredicates(){
		// get the required predicates and remove all predefined predicates, because they have dedicated checks and errors
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
	 * This method will efficiently check if a required predicate is satisfied or not.
	 * This method is used in @fastCheckRequiredPredicates and in @evaluatePredCond.
	 * @param pred The required predicate that should used to be ensured
	 * @param existingPredicates predicates that are ensured
	 * @return true, if pred is matching any predicate in existingPredicates
	 */
	private boolean fastCheckRequiredPredicate(ISLConstraint pred, Collection<EnsuredCrySLPredicate> existingPredicates) {
		
		// Internally, this will check if the predicate satisfied by finding a contradiction.
		// That is the case when its condition is satisfied and
		// - pred is of type {@link RequiredCrySLPredicate} and
		// 		- pred is ensured, but is required to be not ensured
		// 		- pred is not ensured, but is required to be ensured
		// - pred is of type {@link AlternativeReqPredicate} and
		//		- all alternative negated predicates (preds that should be not ensured) are ensured
		//			& all alternative predicates (preds that should be ensured) are not ensured
		//
		// If no contradiction was found, the required pred has to be satisfied.
		
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
				if(existingPredicates.isEmpty() || !existingPredicates.parallelStream().anyMatch(ensPred -> ensPred.getPredicate().equals(reqPred.getPred()) && doPredsParametersMatch(reqPred.getPred(), ensPred))) {
					// predicate is not ensured, but is required to be ensured
					if(isPredConditionSatisfied(reqPred.getPred())) {
						// also condition is satisfied
						return false;
					}
				}
			}
		} else {
			List<CrySLPredicate> alternatives = Lists.newArrayList(((AlternativeReqPredicate) pred).getAlternatives());
			List<CrySLPredicate> negatives = alternatives.parallelStream().filter(e -> e.isNegated()).collect(Collectors.toList()); // holds all negated alternative preds
		
			// TODO check if it is faster to first check positives and then negatives
			if (negatives.isEmpty() || negatives.parallelStream().allMatch(e -> 
				existingPredicates.parallelStream().anyMatch(ensPred -> ensPred.getPredicate().equals(e) && doPredsParametersMatch(e, ensPred)))) {
				// all negative alternative preds are ensured
				List<CrySLPredicate> positives = alternatives.parallelStream().filter(e -> !e.isNegated()).collect(Collectors.toList()); // now check the positives
				if (positives.isEmpty() || !positives.parallelStream().anyMatch(e -> 
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
		// no contradiction found.
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
							// throw a predicate contradiction error
							// remainingRequiredPredicates.add(reqPred);
						}
					}
					else {
						if(existingEnsuredPredicates.isEmpty() || !existingEnsuredPredicates.parallelStream().anyMatch(ensPred -> ensPred.getPredicate().equals(reqPred.getPred()) && doPredsParametersMatch(reqPred.getPred(), ensPred))) {
							// predicate is not ensured, but is required to be ensured
							// throw a required predicate error
							
							reportRequiredPredicateError(reqPred);
						}
					}
				}
			} else {
				List<CrySLPredicate> alternatives = Lists.newArrayList(((AlternativeReqPredicate) pred).getAlternatives());
				List<CrySLPredicate> negatives = alternatives.parallelStream().filter(e -> e.isNegated()).collect(Collectors.toList()); // holds all negated alternative preds
			
				if(alternatives.parallelStream().allMatch(p -> isPredConditionSatisfied(p))) {
					// all conditions are satisfied
					// TODO check if it is faster to first check positives and then negatives
					if (!alternatives.isEmpty() && (negatives.isEmpty() || negatives.parallelStream().allMatch(e -> 
						existingEnsuredPredicates.parallelStream().anyMatch(ensPred -> ensPred.getPredicate().equals(e) && doPredsParametersMatch(e, ensPred))))) {
						// all negative alternative preds are ensured
						List<CrySLPredicate> positives = alternatives.parallelStream().filter(e -> !e.isNegated()).collect(Collectors.toList()); // now check the positives
						if (positives.isEmpty() || !positives.parallelStream().anyMatch(e -> 
						existingEnsuredPredicates.parallelStream().anyMatch(ensPred -> ensPred.getPredicate().equals(e) && doPredsParametersMatch(e, ensPred)))) {
							// also no positiv alternative pred is ensured
							// hence the alternative pred is not ensured
							remainingRequiredPredicates.add(pred);
						}
					}
				}
			}
		}
		this.missingPredicates = remainingRequiredPredicates;
		this.missingPredicatesWithDarkPreds = remainingRequiredPredicatesWithDarkPreds;
		this.neededDarkPreds = usedDarkPredicates;
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
	
	public Collection<AbstractError> reportAndReturnIfPredConditionNotSatisfied(ISLConstraint conditional) {
		if (conditional == null) {
			return Sets.newHashSet();
		}
		//condition could be a constraint or a pred
		if(conditional instanceof CrySLPredicate && !ConstraintSolver.predefinedPreds.contains(((CrySLPredicate) conditional).getPredName())) {
			if(fastCheckRequiredPredicate(new RequiredCrySLPredicate((CrySLPredicate)conditional, null), this.ensuredPredicates)) {
				// condition is satisfied
				return Sets.newHashSet();
			} else {
				// condition  is not satisfied
				RequiredCrySLPredicate missingPred = retrieveValuesForPred(conditional);
				if(missingPred == null) {
					return Sets.newHashSet();
				}
				return reportRequiredPredicateError(missingPred);
			}
		}
		else {
			EvaluableConstraint evalCons = constraintSolver.createConstraint(conditional);
			evalCons.evaluate();
			if (evalCons.hasErrors()) {
				return evalCons.getErrors();
			}
			return Sets.newHashSet();
		}
	}

	private boolean doPredsParametersMatch(CrySLPredicate pred, EnsuredCrySLPredicate ensPred) {
		if(pred.getParameters().size() != ensPred.getParameterToAnalysisSeed().length) {
			return false;
		}
		for(int i=0; i<pred.getParameters().size(); i++) {
			ICrySLPredicateParameter param = pred.getParameters().get(i);
			if(param.getName().equals("_") || ensPred.getPredicate().getParameters().get(i).getName().equals("_")) {
				// this can be anything
				continue;
			}
			IAnalysisSeed seedAtParamI = ensPred.getParameterToAnalysisSeed()[i];
			if(param.getName().equals("this")){
				if((seedAtParamI == null || !seedAtParamI.equals(this))) {
					// this is not this seed
					return false;
				}
				else {
					// this is also this seed
					continue;
				}
			}
			if(param instanceof CrySLMethod) {
				// methods are only defined for prefined predicates (noCallTo etc.)
				return false;
			}
			if(param instanceof CrySLObject) {
				CrySLObject paramObj = (CrySLObject) param;
				
				if(!isOfNonTrackableType(param.getName())) {
					// try to collect expected values for param
					Collection<String> expVals = Collections.emptySet();
					for (CallSiteWithParamIndex cswpi : parameterAnalysis.getCollectedValues().keySet()) {
						if (cswpi.getVarName().equals(param.getName())) {
							expVals = retrieveValueFromUnit(cswpi, parameterAnalysis.getCollectedValues().get(cswpi));
						}
					}
					
					if(!expVals.isEmpty()) {
						// required predicate holds a value, not an object
						Collection<String> actVals = Collections.emptySet();
						for (CallSiteWithParamIndex cswpi : ensPred.getParametersToValues().keySet()) {
							if (cswpi.getVarName().equals(ensPred.getPredicate().getParameters().get(i).getName())) {
								actVals = retrieveValueFromUnit(cswpi, ensPred.getParametersToValues().get(cswpi));
							}
						}
						String splitter = "";
						int index = -1;
						if (paramObj.getSplitter() != null) {
							splitter = paramObj.getSplitter().getSplitter();
							index = paramObj.getSplitter().getIndex();
						}
						for (String foundVal : expVals) {
							if (index > -1) {
								foundVal = foundVal.split(splitter)[index];
							}
							actVals = actVals.parallelStream().map(e -> e.toLowerCase()).collect(Collectors.toList());
							if(!actVals.contains(foundVal.toLowerCase())) {
								return false;
							}
						}
					}
				} else {
					// TODO Refactor
					// required predicate could still be references to other objects
					IAnalysisSeed ensSeed = ensPred.getParameterToAnalysisSeed()[i];
					IAnalysisSeed reqSeed = null;
					if(ensSeed != null) {
						Stmt ensStmt = ensSeed.stmt().getUnit().get();
						if(ensSeed instanceof AnalysisSeedWithSpecification) {
							AnalysisSeedWithSpecification ensSeedWithSpec = (AnalysisSeedWithSpecification) ensSeed;
							String ensClassName = ensSeedWithSpec.getSpec().getRule().getClassName();
							
							checkValues:
							for (CallSiteWithParamIndex cswpi : parameterAnalysis.getCollectedValues().keySet()) {
								if (cswpi.getVarName().equals(param.getName())) {
									for(ExtractedValue q : parameterAnalysis.getCollectedValues().get(cswpi)) {
										// q is a value, that matches 
										
										if(ensStmt instanceof AssignStmt && q.stmt().getUnit().get() instanceof AssignStmt) {
											// important for classes such as SecretKey, where the seed statement is an assign statement
											AssignStmt qStmt = (AssignStmt) q.stmt().getUnit().get();
											RefType qRefType = (RefType) qStmt.getLeftOpBox().getValue().getType();
											String qClassName = qRefType.getSootClass().getName();
											String qShortClassName = qRefType.getSootClass().getShortName();
											
											if(!ensClassName.equals(qClassName) && !ensClassName.equals(qShortClassName)) {
												// the required seed cannot match the ensured seed
												// they must specify the same class
												continue;
											}
											if(!ensStmt.toString().equals(qStmt.toString())) {
												// the required seed cannot match the ensured seed
												// they must be defined on the same statement
												continue;
											}
											
											for (ClassSpecification spec : cryptoScanner.getClassSpecifictions()) {
												// check if refType is matching type of spec
												if (spec.getRule().getClassName().equals(qClassName) || spec.getRule().getClassName().equals(qShortClassName)) {
													AllocVal val = new AllocVal(qStmt.getLeftOp(), q.stmt().getMethod(), qStmt.getRightOp(), new Statement(qStmt, q.stmt().getMethod()));
													reqSeed = this.cryptoScanner.getOrCreateSeedWithSpec(new AnalysisSeedWithSpecification(this.cryptoScanner, q.stmt(), val, spec));
													break checkValues;
												}
											}
										}
										else if(ensStmt instanceof InvokeStmt && q.stmt().getUnit().get() instanceof InvokeStmt) {
											// important for classes such as SecretKey, where the seed statement is an assign statement
											InvokeStmt qStmt = (InvokeStmt) q.stmt().getUnit().get();
											Val val = new Val(q.getValue(), q.stmt().getMethod());
											if(val.getType() instanceof RefType) {
												RefType qRefType = (RefType) val.getType();
												String qClassName = qRefType.getSootClass().getName();
												String qShortClassName = qRefType.getSootClass().getShortName();
											
												if(!ensClassName.equals(qClassName) && !ensClassName.equals(qShortClassName)) {
													// the required seed cannot match the ensured seed
													// they must specify the same class
													continue;
												}
												if(!ensStmt.toString().equals(qStmt.toString())) {
													// the required seed cannot match the ensured seed
													// they must be defined on the same statement
													continue;
												}
												
												for (ClassSpecification spec : cryptoScanner.getClassSpecifictions()) {
													// check if refType is matching type of spec
													if (spec.getRule().getClassName().equals(qClassName) || spec.getRule().getClassName().equals(qShortClassName)) {
														reqSeed = this.cryptoScanner.getOrCreateSeedWithSpec(new AnalysisSeedWithSpecification(this.cryptoScanner, q.stmt(), val, spec));
														break checkValues;
													}
												}
											}
										}
									}
								}
							}
						}
						else {
							AnalysisSeedWithEnsuredPredicate ensSeedWithEnsPred = (AnalysisSeedWithEnsuredPredicate) ensSeed;
							checkValues:
							for (CallSiteWithParamIndex cswpi : parameterAnalysis.getCollectedValues().keySet()) {
								if (cswpi.getVarName().equals(param.getName())) {
									for(ExtractedValue q : parameterAnalysis.getCollectedValues().get(cswpi)) {
										if(ensStmt instanceof AssignStmt && q.stmt().getUnit().get() instanceof AssignStmt) {
											AssignStmt as = (AssignStmt) q.stmt().getUnit().get();
											Value leftOp = as.getLeftOp();
											AllocVal val = new AllocVal(leftOp, q.stmt().getMethod(), as.getRightOp(), new Statement(as, q.stmt().getMethod()));
											reqSeed = this.cryptoScanner.getOrCreateSeed(new Node<Statement, Val>(q.stmt(), val));
											break checkValues;
										}
										else if(ensStmt instanceof InvokeStmt && q.stmt().getUnit().get() instanceof InvokeStmt) {
											Val val = new Val(q.getValue(), q.stmt().getMethod());
											reqSeed = this.cryptoScanner.getOrCreateSeed(new Node<Statement, Val>(q.stmt(), val));
											break checkValues;
										}
										else {
											// TODO this should be done better
											if(q.stmt().getMethod().getActiveBody().getUnits().contains(ensStmt)) {
												reqSeed = ensSeed;
											}	
										}
									}
								}
							}
							
						}
						
					}
					if(reqSeed == null || !reqSeed.equals(ensSeed)) {
						return false;
					}
				}
			}
		}
		return true;
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
				}
			}
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
	
	public Statement retriveFirstStatementForParameterList(Collection<ICrySLPredicateParameter> parameters) {
		for(ICrySLPredicateParameter param: parameters) {
			Statement stmt = retrieveStatementForName(param.getName());
			if(stmt != null) {
				return stmt;
			}
		}
		return null;
	}
	
	public Statement retrieveStatementForName(String name) {
		if (name.equals("transformation"))
			return null;
		if(name.equals("this"))
			return this.stmt();
		for (CallSiteWithParamIndex cwpi : this.parameterAnalysis.getAllQuerySites()) {
			if (cwpi.getVarName().equals(name)) {
				return cwpi.stmt();
			}
		}
		return null;
	}
	
	private Collection<AbstractError> reportRequiredPredicateError(RequiredCrySLPredicate missingPred) {
		Collection<AbstractError> errors = generateRequiredPredicateError(missingPred);
		for(AbstractError error: errors) {
			this.addError(error);
			this.cryptoScanner.getAnalysisListener().reportError(this, error);
		}
		return errors;
	}
	
	public Collection<AbstractError> generateRequiredPredicateError(RequiredCrySLPredicate missingPred){
		Collection<AbstractError> errors = Sets.newHashSet();
		for(CallSiteWithParamIndex v : this.getParameterAnalysis().getAllQuerySites()) {
			if (missingPred.getInvolvedVarNames().contains(v.getVarName()) && missingPred.getLocation().equals(v.stmt())) {
				RequiredPredicateError e = new RequiredPredicateError(missingPred.getPred(), missingPred.getLocation(), this.getSpec().getRule(), new CallSiteWithExtractedValue(v, null));
				errors.add(e);
			}
		}
		// TODO Refactor
		if(missingPred.getPred().getParameters().stream().anyMatch(param -> param instanceof CrySLObject && ((CrySLObject) param).getName().equals("this"))) {
			// edge cases that would produce new errors
			RequiredPredicateError e = new RequiredPredicateError(missingPred.getPred(), missingPred.getLocation(), this.getSpec().getRule(), new CallSiteWithExtractedValue(new CallSiteWithParamIndex(missingPred.getLocation(), null, 0, "this"), null));
			if(getSpec().getRule().getClassName().equals("javax.crypto.SecretKey") && missingPred.getPred().getPredName().equals("generatedKey")) {
				return errors;
			}
			if(getSpec().getRule().getClassName().equals("java.security.KeyPair") && missingPred.getPred().getPredName().equals("generatedKeypair")) {
				return errors;
			}
			errors.add(e);
		}
		return errors;
	}
	
	public Collection<DarkPredicate> getMatchingDarkPredicates(CrySLPredicate pred) {
		return darkPredicates.stream().filter(darkPred -> darkPred.getPredicate().getPredName().equals(pred.getPredName()) && doPredsParametersMatch(pred, darkPred)).collect(Collectors.toSet());
	}

	public final static List<String> trackedTypes = Arrays.asList("java.lang.String", "int", "java.lang.Integer");

	private boolean isOfNonTrackableType(String varName) {
		for (Entry<String, String> object : spec.getRule().getObjects()) {
			if (object.getValue().equals(varName) && trackedTypes.contains(object.getKey())) {
				return false;
			}
		}
		return true;
	}

	

	/**
	 * Returns true, if the predicate is ensured after the state {@param stateNode}.
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
	
	public RequiredCrySLPredicate retrieveValuesForPred(ISLConstraint cons) {
		CrySLPredicate pred = (CrySLPredicate) cons;
		for (CallSiteWithParamIndex cwpi : this.parameterAnalysis.getAllQuerySites()) {
			for (ICrySLPredicateParameter p : pred.getParameters()) {
				// TODO: FIX Cipher rule
				if (p.getName().equals("transformation"))
					continue;
				if (cwpi.getVarName().equals(p.getName())) {
					return new RequiredCrySLPredicate(pred, cwpi.stmt());
				}
			}
		}
		if(pred.getParameters().stream().anyMatch(param -> param.getName().equals("this"))) {
			return new RequiredCrySLPredicate(pred, this.stmt());
		}
		return null;
	}
	
	//
	//
	// GENERAL METHODS
	//
	//
	
	@Override
	public String toString() {
		return "AnalysisSeed [" + super.toString() + " with spec " + spec.getRule().getClassName() + "]";
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

	//
	//
	// GETTER & SETTER METHODS
	//
	//
	
	public ClassSpecification getSpec() {
		return spec;
	}
	
	public ExtractParameterAnalysis getParameterAnalysis() {
		return parameterAnalysis;
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
	
}
