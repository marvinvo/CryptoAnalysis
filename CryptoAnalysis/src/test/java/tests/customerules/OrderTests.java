package tests.customerules;

import org.junit.Test;

import main.prefined.Order;
import test.assertions.Assertions;

public class OrderTests extends UsagePatternTestingFramworkForCustomRules {

	@Test
	public void test1() {
		Order o = new Order();
		o.simpleEvent();
		Assertions.mustNotBeInAcceptingState(o);
		o.simpleEventPlus();
		Assertions.mustNotBeInAcceptingState(o);
		//o.simpleEventStar();
		//o.simpleEventOptional();
		o.multiEventOr1();
		Assertions.mustNotBeInAcceptingState(o);
		//o.multiEventOr2();
		o.multiEventPlusOr1();
		Assertions.mustNotBeInAcceptingState(o);
		//o.multiEventPlusOr2();
		o.multiEventPlusComma1();
		Assertions.mustNotBeInAcceptingState(o);
		o.multiEventPlusComma2();
		//o.multiEventStarOr1();
		//o.multiEventStarOr2();
		//o.multiEventStarComma1();
		//o.multiEventStarComma2();
		Assertions.mustBeInAcceptingState(o);
	}
	
	@Test
	public void test2() {
		Order o = new Order();
		o.simpleEvent();
		Assertions.mustNotBeInAcceptingState(o);
		o.simpleEventPlus();
		Assertions.mustNotBeInAcceptingState(o);
		o.simpleEventStar();
		o.simpleEventOptional();
		o.multiEventOr1();
		Assertions.mustNotBeInAcceptingState(o);
		//o.multiEventOr2();
		o.multiEventPlusOr1();
		Assertions.mustNotBeInAcceptingState(o);
		o.multiEventPlusOr2();
		o.multiEventPlusComma1();
		Assertions.mustNotBeInAcceptingState(o);
		o.multiEventPlusComma2();
		o.multiEventStarOr1();
		o.multiEventStarOr2();
		Assertions.mustBeInAcceptingState(o);
		o.multiEventStarComma1();
		Assertions.mustNotBeInAcceptingState(o);
		o.multiEventStarComma2();
		Assertions.mustBeInAcceptingState(o);
	}
	
	@Test
	public void typeStateErrorTest1() {
		Order o = new Order();
		o.simpleEventPlus();
		Assertions.typestateErrors(1);
	}
	
	@Test
	public void typeStateErrorTest2() {
		Order o = new Order();
		o.simpleEvent();
		o.simpleEventPlus();
		o.simpleEventStar();
		o.simpleEventOptional();
		// o.multiEventOr1();
		o.multiEventPlusOr1();
		Assertions.typestateErrors(1);
	}
	
	@Test
	public void typeStateErrorTest3() {
		Order o = new Order();
		o.simpleEvent();
		o.simpleEventPlus();
		o.simpleEventStar();
		o.simpleEventOptional();
		o.multiEventOr1();
		o.multiEventPlusOr1();
		o.multiEventPlusComma2();
		Assertions.typestateErrors(1);
	}
	
	@Test
	public void typeStateErrorTest4() {
		Order o = new Order();
		o.simpleEvent();
		o.simpleEventPlus();
		o.simpleEventStar();
		o.simpleEventOptional();
		o.multiEventOr1();
		o.multiEventPlusOr1();
		o.multiEventPlusComma1();
		o.multiEventPlusComma2();
		o.multiEventStarOr1();
		o.multiEventStarOr2();
		o.multiEventStarComma2();
		Assertions.typestateErrors(1);
	}
}
