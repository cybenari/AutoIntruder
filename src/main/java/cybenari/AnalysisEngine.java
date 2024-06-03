package cybenari;


import java.util.ArrayList;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import cybenari.rules.AbstractRule;

public class AnalysisEngine {

	private Logging logging;

	public AnalysisEngine(Logging logging) {

		this.logging = logging;
	}

	// analyzes whether a URL is suitable of any of our attacks
	public ArrayList<AttackCandidate> analyzeRequest(ProxyHttpRequestResponse requestResponse, MatchRule rule) {

		ArrayList<AttackCandidate> attackCandidates = new ArrayList<>();

		if (isParamRuleMatch(requestResponse, rule)) {
			attackCandidates = createAttackCandidates(requestResponse, rule);

		}

		return attackCandidates;
	}

	// analyzes whether a URL is suitable of any of our attacks
	public ArrayList<AttackCandidate> analyzeRequest(ProxyHttpRequestResponse requestResponse,
			ArrayList<AbstractRule> rules, MatchRule paramRule) {

		ArrayList<AttackCandidate> attackCandidates = new ArrayList<>();

		attackCandidates = createAttackCandidates(requestResponse, rules, paramRule);

		return attackCandidates;
	}

	// this method is for checking the configuration on the parameter and not the
	// request filter rules
	private boolean isParamRuleMatch(ProxyHttpRequestResponse requestResponse, MatchRule rule) {

		// check if rule url regex matches the request url if
		if (!rule.isPathMatchingRule(requestResponse.request().path())) {

			return false;
		}

		if (!rule.IsMethodMatching(requestResponse.request().method())) {

			return false;
		}

		return true;
	}

	//in order for request to be replaced 3 thins need to match:
	//1) Request Filter Rules (AbstractRules)
	//2) method type rules (GET,POST..)
	//3) Parameter Type rules (Body,URL,PATH)
	private ArrayList<AttackCandidate> createAttackCandidates(ProxyHttpRequestResponse requestResponse,
			ArrayList<AbstractRule> rules, MatchRule paramRule) {
		ArrayList<AttackCandidate> attackCandidates = new ArrayList<>();

		// and - rule must match ALL ands
		// or - rule must match at least one OR
		ArrayList<AbstractRule> andRules = new ArrayList<AbstractRule>();
		ArrayList<AbstractRule> orRules = new ArrayList<AbstractRule>();

		for (AbstractRule rule : rules) {
			if (rule.getOperation() == AbstractRule.OPERATION.AND) {
				andRules.add(rule);
			} else {
				orRules.add(rule);
			}
		}

		boolean allAndRulesMatch = allAndRulesMatch(andRules, requestResponse);
		boolean atLeastOneOrRuleMatches = atLeastOneOrRuleMatches(orRules, requestResponse);

	
		if (allAndRulesMatch || atLeastOneOrRuleMatches) {
			
				if (paramRule.isBodyParamEnabled()) {
				attackCandidates.addAll(paramRule.findPatternInBody(requestResponse));
				}
				if (paramRule.isURLParamEnabled()) {
				attackCandidates.addAll(paramRule.findPatternsInQuery(requestResponse));
				}
				if (paramRule.isPathParamEnabled()) {
				attackCandidates.addAll(paramRule.findPatternsInPath(requestResponse));
				}
			
			return attackCandidates;
		}

		return new ArrayList<>();

	}

	private boolean allAndRulesMatch(ArrayList<AbstractRule> andRules, ProxyHttpRequestResponse requestResponse) {
		if (andRules.size() == 0) {
			return false;
		}
		for (AbstractRule andRule : andRules) {
			if (!andRule.doesMatchRule(requestResponse))
				return false;
		}
		return true;
	}

	private boolean atLeastOneOrRuleMatches(ArrayList<AbstractRule> orRules, ProxyHttpRequestResponse requestResponse) {
		for (AbstractRule orRule : orRules) {
			// if only one rule matches the we create candidates from it
			if (orRule.doesMatchRule(requestResponse)) {
				return true;
			}
		}
		return false;
	}

	// delete this once new way of rule testing is done
	private ArrayList<AttackCandidate> createAttackCandidates(ProxyHttpRequestResponse requestResponse,
			MatchRule rule) {
		ArrayList<AttackCandidate> attackCandidates = new ArrayList<>();

		if (isParamRuleMatch(requestResponse, rule)) {

			if (rule.isBodyParamEnabled()) {
				attackCandidates.addAll(rule.findPatternInBody(requestResponse));
			}

			if (rule.isURLParamEnabled()) {
				attackCandidates.addAll(rule.findPatternsInQuery(requestResponse));
			}

			if (rule.isPathParamEnabled()) {
				attackCandidates.addAll(rule.findPatternsInPath(requestResponse));
			}

		}

		return attackCandidates;
	}

	/*
	 * // checks all attack on all segments for a fit and returns an arraylist of
	 * all // test candidates private ArrayList<AttackCandidate>
	 * analyzeAllTestsOnAllSegments(HttpRequest request) {
	 * 
	 * ArrayList<AttackCandidate> testCandidates = new ArrayList<>();
	 * 
	 * for (AbstractAttackType attack : attacks) { if
	 * (attack.isSuitableForAttack(request)) {
	 * 
	 * String result = "Found suitable: " + (attack.getAttackTypeName()).toString()
	 * + " url: " + request.url(); System.out.println(result);
	 * 
	 * testCandidates.addAll(attack.createAttackCandidates(request));
	 * 
	 * // testCandidates.addAll(attack.createAttackRequests(url)); } }
	 * 
	 * 
	 * 
	 * return testCandidates; }
	 */
}
