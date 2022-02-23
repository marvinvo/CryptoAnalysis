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
	private Multimap<Statement, State> typeStateChange = HashMultimap.create();
	private Collection<EnsuredCrySLPredicate> indirectlyEnsuredPredicates = Sets.newHashSet();
	private Set<ISLConstraint> missingPredicates = Sets.newHashSet();
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
					cryptoScanner.getAnalysisListener().reportError(this, new IncompleteOperationError(s, val, getSpec().getRule(), this, expectedMethodsToBeCalled));
				}
			}
		}
	}

	private void typeStateChangeAtStatement(Statement curr, State stateNode) {
		if (typeStateChange.put(curr, stateNode)) {
			if (stateNode instanceof ReportingErrorStateNode) {
				ReportingErrorStateNode errorStateNode = (ReportingErrorStateNode) stateNode;
				cryptoScanner.getAnalysisListener().reportError(this, new TypestateError(curr, getSpec().getRule(), this, errorStateNode.getExpectedCalls()));
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
			else {
				// dark preds could be added (ensured) here
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
		boolean satisfiesConstraintSytem = checkConstraintSystem();
		if(predToBeEnsured.getConstraint() != null) {
			satisfiesConstraintSytem = !evaluatePredCond(predToBeEnsured);
		}
		
		// check if expect predicate when *this* object is in state
		for (ICrySLPredicateParameter predicateParam : predToBeEnsured.getParameters()) {
			if (predicateParam.getName().equals("this")) {
				expectPredicateWhenThisObjectIsInState(stateNode, currStmt, predToBeEnsured, satisfiesConstraintSytem);
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
					expectPredicateOnOtherObject(predToBeEnsured, currStmt, val, satisfiesConstraintSytem);
				}
				int i = 0;
				for (Entry<String, String> p : crySLMethod.getParameters()) {
					if (predicateParameterEquals(predToBeEnsured.getParameters(), p.getKey())) {
						Value param = ie.getArg(i);
						if (param instanceof Local) {
							Val val = new Val(param, currStmt.getMethod());
							expectPredicateOnOtherObject(predToBeEnsured, currStmt, val, satisfiesConstraintSytem);
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
	private void expectPredicateOnOtherObject(CrySLPredicate predToBeEnsured, Statement currStmt, Val accessGraph, boolean satisfiesConstraintSytem) {
		// TODO refactor this method.
		
		// check, if parameter is of a type with specification rules
			//boolean matched = false;
		if (accessGraph.value() != null && satisfiesConstraintSytem) {
			Type baseType = accessGraph.value().getType();
			if (baseType instanceof RefType) {
				RefType refType = (RefType) baseType;
				
				for (ClassSpecification spec : cryptoScanner.getClassSpecifictions()) {
					// check if refType is matching type of spec
					if (spec.getRule().getClassName().equals(refType.getSootClass().getName()) || spec.getRule().getClassName().equals(refType.getSootClass().getShortName())) {
						AnalysisSeedWithSpecification seed = cryptoScanner.getOrCreateSeedWithSpec(new AnalysisSeedWithSpecification(cryptoScanner, currStmt, accessGraph, spec));
							//matched = true;
						seed.addEnsuredPredicateFromOtherRule(new EnsuredCrySLPredicate(predToBeEnsured, parameterAnalysis.getCollectedValues()));
						// we could return here, because both class specifications and parameter reference should be unique regarding their types
						return;
					}
				}
			}
		}
		//if (matched)
		//return;
		
		// found no specification for the given parameter type
		AnalysisSeedWithEnsuredPredicate seed = cryptoScanner.getOrCreateSeed(new Node<Statement, Val>(currStmt, accessGraph));
		predicateHandler.expectPredicate(seed, currStmt, predToBeEnsured);
		if (satisfiesConstraintSytem) {
			seed.addEnsuredPredicate(new EnsuredCrySLPredicate(predToBeEnsured, parameterAnalysis.getCollectedValues()));
		} else {
			missingPredicates.add(new RequiredCrySLPredicate(predToBeEnsured, currStmt));
		}
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
	private void expectPredicateWhenThisObjectIsInState(State stateNode, Statement currStmt, CrySLPredicate predToBeEnsured, boolean satisfiesConstraintSytem) {
		predicateHandler.expectPredicate(this, currStmt, predToBeEnsured);

		if (!satisfiesConstraintSytem)
			return;
		for (Cell<Statement, Val, TransitionFunction> e : results.asStatementValWeightTable().cellSet()) {
			// TODO check for any reachable state that don't kill
			// predicates.
			if (containsTargetState(e.getValue(), stateNode)) {
				predicateHandler.addNewPred(this, e.getRowKey(), e.getColumnKey(), new EnsuredCrySLPredicate(predToBeEnsured, parameterAnalysis.getCollectedValues()));
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

	private boolean checkConstraintSystem() {
		cryptoScanner.getAnalysisListener().beforePredicateCheck(this);
		Set<ISLConstraint> relConstraints = constraintSolver.getRelConstraints();
		boolean checkPredicates = checkPredicates(relConstraints);
		cryptoScanner.getAnalysisListener().afterPredicateCheck(this);
		if (!checkPredicates)
			return false;
		return internalConstraintSatisfied;
	}

	/**
	 * Checks the required predicates (only preds appearing in REQUIRED section, not in CONSTRAINTS)
	 * and will add missing predicates to {@missingPredicates}.
	 * @param relConstraints
	 * @return
	 */
	private boolean checkPredicates(Collection<ISLConstraint> relConstraints) {
		
		// get the required predicates
		List<ISLConstraint> requiredPredicates = Lists.newArrayList();
		for (ISLConstraint con : constraintSolver.getRequiredPredicates()) {
			if (!ConstraintSolver.predefinedPreds.contains((con instanceof RequiredCrySLPredicate) ? ((RequiredCrySLPredicate) con).getPred().getPredName()
					: ((AlternativeReqPredicate) con).getAlternatives().get(0).getPredName())) {
				// TODO predefined preds could be in alternatives anyways and will be checked at the method end
				requiredPredicates.add(con);
			}
		}
		Set<ISLConstraint> remainingPredicates = Sets.newHashSet(requiredPredicates);
		
		missingPredicates.removeAll(remainingPredicates);

		//
		// Check if the right side of a constraint is fulfilled
		//
		for (ISLConstraint pred : requiredPredicates) {
			if (pred instanceof RequiredCrySLPredicate) {
				RequiredCrySLPredicate reqPred = (RequiredCrySLPredicate) pred;
				if (reqPred.getPred().isNegated()) {
					for (EnsuredCrySLPredicate ensPred : ensuredPredicates) {
						if (ensPred.getPredicate().equals(reqPred.getPred())) {
							// a predicate is ensured, that is required to be not ensured.
							// TODO equals method will only check if predicates have the same name, not same parameter.
							return false;
						}
					}
					remainingPredicates.remove(pred);
				} else {
					for (EnsuredCrySLPredicate ensPred : ensuredPredicates) {
						if (ensPred.getPredicate().equals(reqPred.getPred()) && doPredsMatch(reqPred.getPred(), ensPred)) {
							// a predicate is ensured, that is required to be ensured.
							// hence it can be removed from missing predicates
							remainingPredicates.remove(pred);
						}
					}
				}
			} else {
				AlternativeReqPredicate alt = (AlternativeReqPredicate) pred;
				List<CrySLPredicate> alternatives = alt.getAlternatives();
				
				// holds all negated alternative preds
				List<CrySLPredicate> negatives = alternatives.parallelStream().filter(e -> e.isNegated()).collect(Collectors.toList());
				
				if (negatives.size() == alternatives.size()) {
					// all alternatives are negated
					for (EnsuredCrySLPredicate ensPred : ensuredPredicates) {
						if (alternatives.parallelStream().anyMatch(e -> e.getPredName().equals(ensPred.getPredicate().getPredName()))) {
							// TODO alternatives are for example: 
							// !pred1 OR !pred2
							// so alternatives would hold [pred1, pred2]
							// Hence it should not return false when only some of the preds are ensured, as long as one is not.
							// It should return false, if and only if **ALL** preds are ensured.
							return false;
						}
					}
					remainingPredicates.remove(pred);
				} else if (negatives.isEmpty()) {
					// all alternatives are not negated
					for (EnsuredCrySLPredicate ensPred : ensuredPredicates) {
						if (alternatives.parallelStream().anyMatch(e -> ensPred.getPredicate().equals(e) && doPredsMatch(e, ensPred))) {
							// any of the alternatives is ensured, hence it can be removed from missing required preds
							remainingPredicates.remove(pred);
							break;
						}
					}
				} else {
					// there are some negated and some non-negated preds
					boolean neg = true;
					boolean satisfied = false;

					for (EnsuredCrySLPredicate ensPred : ensuredPredicates) {
						if (negatives.parallelStream().anyMatch(e -> e.equals(ensPred.getPredicate()))) {
							neg = false;
						}

						alternatives.removeAll(negatives);
						if (alternatives.parallelStream().allMatch(e -> ensPred.getPredicate().equals(e) && doPredsMatch(e, ensPred))) {
							satisfied = true;
						}

						if (satisfied | neg) {
							remainingPredicates.remove(pred);
						}
					}
				}

			}
		}

		// evaluate conditions for remaining preds.
		// if the condition is not fulfilled, the pred has to be neither.
		// hence it could be removed from missing pred list.
		for (ISLConstraint rem : Lists.newArrayList(remainingPredicates)) {
			if (rem instanceof RequiredCrySLPredicate) {
				RequiredCrySLPredicate singlePred = (RequiredCrySLPredicate) rem;
				if (evaluatePredCond(singlePred.getPred())) {
					// condition for pred has errors, hence its constraint is fulfilled
					remainingPredicates.remove(singlePred);
				}
			} else if (rem instanceof CrySLConstraint) {
				List<CrySLPredicate> altPred = ((AlternativeReqPredicate) rem).getAlternatives();
				if (altPred.parallelStream().anyMatch(e -> evaluatePredCond(e))) {
					// there is one condition of an alternative pred having errors, hence the constraint is fulfilled
					
					// TODO imagine one pred is negated, then it should be also removed if the pred 
					remainingPredicates.remove(rem);
				}
			}
		}

		this.missingPredicates.addAll(remainingPredicates);
		return remainingPredicates.isEmpty();
	}

	private boolean evaluatePredCond(CrySLPredicate pred) {
		final ISLConstraint conditional = pred.getConstraint();
		if (conditional != null) {
			EvaluableConstraint evalCons = constraintSolver.createConstraint(conditional);
			evalCons.evaluate();
			if (evalCons.hasErrors()) {
				return true;
			}
		}
		return false;
	}

	private boolean doPredsMatch(CrySLPredicate pred, EnsuredCrySLPredicate ensPred) {
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
		return pred.isNegated() != requiredPredicatesExist;
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
		if (ensuredPredicates.add(ensPred)) {
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

	public Set<ISLConstraint> getMissingPredicates() {
		return missingPredicates;
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
