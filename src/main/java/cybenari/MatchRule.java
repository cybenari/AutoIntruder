package cybenari;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import cybenari.AbstractAttackType.AttackTypeName;
import cybenari.AttackCandidate.REPLACE_TYPE;

public class MatchRule {

	private boolean inScopeOnly = true;
	private boolean getMethodEnabled = true;
	private boolean postMethodEnabled = true;
	private boolean optionsMethodEnabled = false;
	private boolean putMethodEnabled = false;
	private boolean patchMethodEnabled = true;
	private boolean deleteMethodEnabled = false;
	private boolean matchParamName = false;
	private boolean matchParamValue = true;
	private int maxConcurrentRequests = 1;
	private int requestDelay = 100;
	private Pattern pathPattern;
	private String defaultPathPattern = "\\/.*";
	private Pattern parameterPattern;
	private String defaultParameterPattern = "([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12})";
	private String matchPlaceHolder = "§";
	private boolean isBodyParamEnabled = true;
	private boolean isPathParamEnabled = true;
	private boolean isURLParamEnabled = true;
	private boolean isHeaderValuesEnabled = true;
	

	public MatchRule() {

		this.pathPattern = Pattern.compile(defaultPathPattern);
		this.parameterPattern = Pattern.compile(defaultParameterPattern);

	}

	public Pattern getParameterPattern() {
		return this.parameterPattern;
	}

	public void setParameterPattern(Pattern pattern) {
		this.parameterPattern = pattern;
	}

	public boolean isInScopeOnly() {
		return inScopeOnly;
	}

	public void setInScopeOnly(boolean inScopeOnly) {
		this.inScopeOnly = inScopeOnly;
	}

	public boolean isGetMethodEnabled() {
		return getMethodEnabled;
	}

	public void setGetMethodEnabled(boolean getMethodEnabled) {
		this.getMethodEnabled = getMethodEnabled;
	}

	public boolean isPostMethodEnabled() {
		return postMethodEnabled;
	}

	public void setPostMethodEnabled(boolean postMethodEnabled) {
		this.postMethodEnabled = postMethodEnabled;
	}

	public boolean isOptionsMethodEnabled() {
		return optionsMethodEnabled;
	}

	public void setOptionsMethodEnabled(boolean optionsMethodEnabled) {
		this.optionsMethodEnabled = optionsMethodEnabled;
	}

	public boolean isPutMethodEnabled() {
		return putMethodEnabled;
	}

	public void setPutMethodEnabled(boolean putMethodEnabled) {
		this.putMethodEnabled = putMethodEnabled;
	}

	public boolean isPatchMethodEnabled() {
		return patchMethodEnabled;
	}

	public void setPatchMethodEnabled(boolean patchMethodEnabled) {
		this.patchMethodEnabled = patchMethodEnabled;
	}

	public boolean isMatchParamName() {
		return matchParamName;
	}

	public void setMatchParamName(boolean matchParamName) {
		this.matchParamName = matchParamName;
	}

	public boolean isMatchParamValue() {
		return matchParamValue;
	}

	public void setMatchParamValue(boolean matchParamValue) {
		this.matchParamValue = matchParamValue;
	}

	public int getMaxConcurrentRequests() {
		return maxConcurrentRequests;
	}

	public void setMaxConcurrentRequests(int maxConcurrentRequests) {
		this.maxConcurrentRequests = maxConcurrentRequests;
	}

	public int getRequestDelay() {
		return requestDelay;
	}

	public void setRequestDelay(int requestDelay) {
		this.requestDelay = requestDelay;
	}

	public Pattern getPathPattern() {
		return this.pathPattern;
	}

	public void setPathPattern(Pattern pathPattern) {
		this.pathPattern = pathPattern;
	}

	public boolean isPathMatchingRule(String path) {

		Matcher matcher = this.getPathPattern().matcher(path);
		return matcher.matches();
	}

	// check if request method matches rules
	public boolean IsMethodMatching(String method) {

		switch (method.toUpperCase()) {
		case "GET":
			return isGetMethodEnabled();
		case "POST":
			return isPostMethodEnabled();
		case "OPTIONS":
			return isOptionsMethodEnabled();
		case "PUT":
			return isPutMethodEnabled();
		case "PATCH":
			return isPatchMethodEnabled();
		default:
			return false;
		}
	}

	// matches places in the body of the request that match the rule and generates
	// new request candidates from it.
	public ArrayList<AttackCandidate> findPatternInBody(ProxyHttpRequestResponse requestResponse) {
		ArrayList<AttackCandidate> attackCandidates = new ArrayList<>();
		HttpRequest request = requestResponse.request();
		String body = request.bodyToString();

		Matcher matcher = getParameterPattern().matcher(body);

		while (matcher.find()) {
			AttackCandidate candidate = new AttackCandidate(request, AttackTypeName.CustomRule);
			String match = matcher.group();
			int matchStart = matcher.start();
			int matchEnd = matcher.end();
			String originalPayload = body.substring(matchStart, matchEnd);
			
			String matchWithPlaceHolders = matchPlaceHolder + match + matchPlaceHolder;

			StringBuffer tempBuffer = new StringBuffer(body);
			// Replace the current match with "placeholder"
			tempBuffer.replace(matcher.start(), matcher.end(), matchWithPlaceHolders);

			// String modified = body.replace(match, matchWithPlaceHolders);

			candidate.setModifiedRequest(request.withBody(tempBuffer.toString()));
			candidate.setOriginalResponse(requestResponse.originalResponse());
			candidate.setOriginalPayload(originalPayload);
			candidate.setReplaceType(REPLACE_TYPE.BODY);
			attackCandidates.add(candidate);

		}

		return attackCandidates;
	}

	public ArrayList<AttackCandidate> findPatternsInQuery(ProxyHttpRequestResponse requestResponse) {
		ArrayList<AttackCandidate> attackCandidates = new ArrayList<>();

		ArrayList<ParsedHttpParameter> parsedParams = new ArrayList<>(
				requestResponse.request().parameters(HttpParameterType.URL));

		for (ParsedHttpParameter originalParam : parsedParams) {
			Matcher matcher = getParameterPattern().matcher(originalParam.value());

			if (matcher.matches()) {
				String newValue = matchPlaceHolder + originalParam.value() + matchPlaceHolder;
				int matchStart = matcher.start();
				int matchEnd = matcher.end();
				String originalPayload = originalParam.value().substring(matchStart, matchEnd);
				
				// generate a new instance of the HttpParam to replace the originalOne
				HttpParameter newParam = HttpParameter.urlParameter(originalParam.name(), newValue);

				AttackCandidate candidate = new AttackCandidate(requestResponse.request(), AttackTypeName.CustomRule);
				candidate.setOriginalResponse(requestResponse.originalResponse());
				candidate.setModifiedRequest(requestResponse.request().withUpdatedParameters(newParam));
				candidate.setOriginalPayload(originalPayload);
				candidate.setReplaceType(REPLACE_TYPE.QUERY);
				attackCandidates.add(candidate);
			}

		}

		return attackCandidates;
	}

	public ArrayList<AttackCandidate> findPatternsInPath(ProxyHttpRequestResponse requestResponse) {
		ArrayList<AttackCandidate> attackCandidates = new ArrayList<>();
		HttpRequest request = requestResponse.request();

		Matcher matcher = getParameterPattern().matcher(request.pathWithoutQuery());

		while (matcher.find()) {

			String match = matcher.group();
			String matchWithPlaceHolders = matchPlaceHolder + match + matchPlaceHolder;
			int matchStart = matcher.start();
			int matchEnd = matcher.end();
			String originalPayload = request.pathWithoutQuery().substring(matchStart, matchEnd);
			
			StringBuffer tempBuffer = new StringBuffer(request.path());
			// Replace the current match with "placeholder"
			tempBuffer.replace(matcher.start(), matcher.end(), matchWithPlaceHolders);

			AttackCandidate attackCandidate = new AttackCandidate(request, AttackTypeName.CustomRule);
			attackCandidate.setModifiedRequest(request.withPath(tempBuffer.toString()));
			attackCandidate.setOriginalResponse(requestResponse.originalResponse());
			attackCandidate.setOriginalPayload(originalPayload);
			attackCandidate.setReplaceType(REPLACE_TYPE.PATH);
			attackCandidates.add(attackCandidate);
		}

		return attackCandidates;
	}
	
	public ArrayList<AttackCandidate> findPatternsInHeaderValues(ProxyHttpRequestResponse requestResponse) {
		ArrayList<AttackCandidate> attackCandidates = new ArrayList<>();
		HttpRequest request = requestResponse.request();
		
		for(HttpHeader header : request.headers()) {
			String headerValue = header.value();
			Matcher matcher = getParameterPattern().matcher(headerValue);
			
			while (matcher.find()) {
				String match = matcher.group();
				String matchWithPlaceHolders = matchPlaceHolder + match + matchPlaceHolder;
				int matchStart = matcher.start();
				int matchEnd = matcher.end();
				String originalPayload = headerValue.substring(matchStart, matchEnd);
				
				StringBuffer tempBuffer = new StringBuffer(headerValue);
				// Replace the current match with "placeholder"
				tempBuffer.replace(matcher.start(), matcher.end(), matchWithPlaceHolders);

				AttackCandidate attackCandidate = new AttackCandidate(request, AttackTypeName.CustomRule);
				attackCandidate.setModifiedRequest(request.withHeader(header.name(), tempBuffer.toString()));
				
				attackCandidate.setOriginalResponse(requestResponse.originalResponse());
				attackCandidate.setOriginalPayload(originalPayload);
				attackCandidate.setReplaceType(REPLACE_TYPE.HEADER_VALUE);
				attackCandidates.add(attackCandidate);
				
			}
		}
		
		return attackCandidates;
		
	}

	public boolean isDeleteMethodEnabled() {
		return deleteMethodEnabled;
	}

	public void setDeleteMethodEnabled(boolean deleteMethodEnabled) {
		this.deleteMethodEnabled = deleteMethodEnabled;
	}

	public String toString() {
		String NEWLINE = System.lineSeparator();

		StringBuilder sb = new StringBuilder();
		sb.append("---- Rule ---").append(NEWLINE);
		sb.append("Enabled Methods:").append(NEWLINE);
		sb.append("GET: ").append(getMethodEnabled).append(NEWLINE);
		sb.append("POST: ").append(postMethodEnabled).append(NEWLINE);
		sb.append("PUT: ").append(putMethodEnabled).append(NEWLINE);
		sb.append("PATCH: ").append(patchMethodEnabled).append(NEWLINE);
		sb.append("OPTIONS: ").append(optionsMethodEnabled).append(NEWLINE);
		sb.append("DELETE: ").append(deleteMethodEnabled).append(NEWLINE);

		sb.append("Path").append(NEWLINE);
		sb.append("Path Pattern:").append(pathPattern.toString()).append(NEWLINE);
		sb.append("Parameter Pattern:").append(parameterPattern.toString()).append(NEWLINE);
		sb.append("---- End of Rule ---").append(NEWLINE);
		return sb.toString();
	}

	public boolean isBodyParamEnabled() {
		return isBodyParamEnabled;
	}

	public void setBodyParamEnabled(boolean isBodyParamEnabled) {
		this.isBodyParamEnabled = isBodyParamEnabled;
	}

	public boolean isPathParamEnabled() {
		return isPathParamEnabled;
	}

	public void setPathParamEnabled(boolean isPathParamEnabled) {
		this.isPathParamEnabled = isPathParamEnabled;
	}

	public boolean isURLParamEnabled() {
		return isURLParamEnabled;
	}

	public void setURLParamEnabled(boolean isURLParamEnabled) {
		this.isURLParamEnabled = isURLParamEnabled;
	}

	public boolean isHeaderValuesEnabled() {
		return isHeaderValuesEnabled;
	}

	public void setHeaderValuesEnabled(boolean isHeaderValuesEnabled) {
		this.isHeaderValuesEnabled = isHeaderValuesEnabled;
	}

}
