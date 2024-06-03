package cybenari.rules;

import burp.api.montoya.proxy.ProxyHttpRequestResponse;

public class InScopeRule extends AbstractRule{

	@Override
	public void setMatchPattern(String matchPattern) {
		return;
		
	}

	@Override
	public boolean doesMatchRule(ProxyHttpRequestResponse requestResponse) {
		if(requestResponse.request() != null) {
			return requestResponse.request().isInScope();
		}
		return false;
	}

	@Override
	public MATCH_TYPE getMatchType() {
		
		return MATCH_TYPE.IN_SCOPE;
	}

}
