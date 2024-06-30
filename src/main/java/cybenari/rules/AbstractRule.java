package cybenari.rules;

import burp.api.montoya.proxy.ProxyHttpRequestResponse;

public abstract class AbstractRule {

	public enum OPERATION {
		AND, OR
	}

	public enum REQUEST_RESPONSE {
		REQUEST, RESPONSE
	}

	public enum MATCH_TYPE {
		PATH, METHOD, IN_SCOPE, COOKIE_NAME, COOKIE_VALUE, HEADER_NAME, HEADER_VALUE, BODY,STATUS_CODE
	}

	private REQUEST_RESPONSE requestOrResponse;
	private MATCH_TYPE matchType;
	private OPERATION operation = OPERATION.OR;
	protected String matchPattern;
	private boolean enabled = true;

	public OPERATION getOperation() {
		return this.operation;
	}

	public void setOperation(OPERATION operation) {
		this.operation = operation;
	}

	public String getMatchPattern() {
		return matchPattern;
	}

	abstract public void setMatchPattern(String matchPattern);

	abstract public boolean doesMatchRule(ProxyHttpRequestResponse requestResponse);

	public boolean isEnabled() {
		return enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	abstract public MATCH_TYPE getMatchType();

	public void setMatchType(MATCH_TYPE matchType) {
		this.matchType = matchType;
	}

	public REQUEST_RESPONSE getRequestOrResponse() {
		return requestOrResponse;
	}

	public void setRequestOrResponse(REQUEST_RESPONSE requestOrResponse) {
		this.requestOrResponse = requestOrResponse;
	}

}
