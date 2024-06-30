package cybenari.rules;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import burp.api.montoya.proxy.ProxyHttpRequestResponse;

public class StatusCodeRule extends AbstractRule{

	@Override
	public void setMatchPattern(String matchPattern) {
		this.matchPattern = matchPattern;
		
	}

	@Override
	public boolean doesMatchRule(ProxyHttpRequestResponse requestResponse) {
		
		if(requestResponse.response() != null) {
			
			Pattern statusCodePattern = Pattern.compile(getMatchPattern());
			Matcher matcher = statusCodePattern.matcher(String.valueOf(requestResponse.response().statusCode()));
			return matcher.matches();
		}
		return false;
	}

	@Override
	public MATCH_TYPE getMatchType() {
		
		return MATCH_TYPE.STATUS_CODE;
	}

}
