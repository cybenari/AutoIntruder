package cybenari.rules;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

public class MethodRule extends AbstractRule{

	@Override
	public void setMatchPattern(String matchPattern) {
		this.matchPattern = matchPattern;
		
	}

	@Override
	public boolean doesMatchRule(ProxyHttpRequestResponse requestResponse) {
		
		HttpRequest request = requestResponse.request();

		if (request != null) {
			Pattern method = Pattern.compile(getMatchPattern());

			if (request.method() != null) {
				Matcher matcher = method.matcher(request.method());

				return matcher.matches();
			}
			return false;
		}
		return false;
	}

	@Override
	public MATCH_TYPE getMatchType() {
		return MATCH_TYPE.METHOD;
	}

	
}
