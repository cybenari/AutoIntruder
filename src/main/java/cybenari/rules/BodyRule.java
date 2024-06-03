package cybenari.rules;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import cybenari.rules.AbstractRule.REQUEST_RESPONSE;

public class BodyRule extends AbstractRule {

	@Override
	public void setMatchPattern(String matchPattern) {
		this.matchPattern = matchPattern;

	}

	@Override
	public boolean doesMatchRule(ProxyHttpRequestResponse requestResponse) {
		String body;
		if (getRequestOrResponse() == REQUEST_RESPONSE.REQUEST) {
			if (requestResponse.request() != null) {
				body = requestResponse.request().bodyToString();
			} else {
				return false;
			}

		} else {
			if (requestResponse.response() != null) {
				body = requestResponse.response().bodyToString();
			} else {
				return false;
			}
		}

		Pattern bodyPattern = Pattern.compile(getMatchPattern());
		Matcher matcher = bodyPattern.matcher(body);
		return matcher.matches();

	}

	@Override
	public MATCH_TYPE getMatchType() {
		
		return  MATCH_TYPE.BODY;
	}

}
