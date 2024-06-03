package cybenari.rules;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

public class PathRule extends AbstractRule {

	@Override
	public void setMatchPattern(String matchPattern) {
		this.matchPattern = matchPattern;

	}

	public boolean doesMatchRule(ProxyHttpRequestResponse requestResponse) {

		HttpRequest request = requestResponse.request();
		if (request != null) {
			Pattern pathPattern = Pattern.compile(getMatchPattern());

			Matcher matcher = pathPattern.matcher(request.path());
			return matcher.matches();

		}
		return false;
	}

	@Override
	public MATCH_TYPE getMatchType() {
		return MATCH_TYPE.PATH;
	}

}
