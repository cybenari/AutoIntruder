package cybenari.rules;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

public class HeaderNameRule extends AbstractRule {

	@Override
	public void setMatchPattern(String matchPattern) {
		this.matchPattern = matchPattern;

	}

	@Override
	public boolean doesMatchRule(ProxyHttpRequestResponse requestResponse) {

		if (getRequestOrResponse() == REQUEST_RESPONSE.REQUEST) {
			
			if (requestResponse.request() != null) {
				return matchInAllHeadersNames(requestResponse.request().headers());
			}
		} else {

			if (requestResponse.response() != null) {
				return matchInAllHeadersNames(requestResponse.response().headers());
			}
		}

		return false;
	}

	private boolean matchInAllHeadersNames(List<HttpHeader> headers) {

		Pattern headerName = Pattern.compile(getMatchPattern());
		for (HttpHeader header : headers) {
			Matcher matcher = headerName.matcher(header.name());
			if (matcher.matches()) {
				return true;
			}
		}
		return false;
	}

	@Override
	public MATCH_TYPE getMatchType() {

		return MATCH_TYPE.HEADER_NAME;
	}

}
