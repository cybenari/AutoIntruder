package cybenari.rules;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import cybenari.rules.AbstractRule.REQUEST_RESPONSE;

public class CookieValueRule extends AbstractRule {

	@Override
	public void setMatchPattern(String matchPattern) {
		this.matchPattern = matchPattern;

	}

	@Override
	public boolean doesMatchRule(ProxyHttpRequestResponse requestResponse) {

		String cookies = requestResponse.request().headerValue("Cookie");
		// try lower c cookie
		if (cookies == null) {
			cookies = requestResponse.request().headerValue("cookie");
		}
		
		//goes over all cookies by spliting ; and then goes over all cookie values by spliting by =. then checks the value
		if (cookies != null) {
			String cookieArray[] = cookies.split(";");
			Pattern cookiePattern = Pattern.compile(getMatchPattern());
			for (int i = 0; i < cookieArray.length; i++) {

				String cookieValue[] = cookieArray[i].split("=");

				if (cookieValue.length > 0) {
					Matcher matcher = cookiePattern.matcher(cookieValue[1]);

					if (matcher.matches()) {
						return true;
					}
				}
			}

		}
		return false;
	}

	@Override
	public MATCH_TYPE getMatchType() {

		return MATCH_TYPE.COOKIE_VALUE;
	}

}
