package cybenari;

import java.util.ArrayList;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import cybenari.AbstractAttackType.AttackTypeName;

public class AttackCandidate {

	public enum REPLACE_TYPE {
		PATH, BODY, QUERY, HEADER_VALUE
	}

	private HttpRequest originalRequest;
	private HttpRequest modifiedRequest;
	private HttpResponse originalResponse;
	private HttpResponse attackResponse;
	private boolean enabled = true;
	private String resultStatus = "Not executed";
	private String payload;
	private String matchPlaceHolder = "§";
	private String replacedPayload = "";
	private REPLACE_TYPE replaceType;

	// private ArrayList<HttpRequestWithPayloads> requestWithPayloads;
	private AttackTypeName attackTypeName;

	public AttackCandidate(HttpRequest originalRequest, AttackTypeName attackTypeName) {
		this.setOriginalRequest(originalRequest);

		this.attackTypeName = attackTypeName;
		// this.requestWithPayloads = new ArrayList<>();
	}

	// creates a clone of the attack candidates and replaces the place holders with
	// payload
	public AttackCandidate cloneWithPayload(String payload) {
		AttackCandidate clone = new AttackCandidate(getOriginalRequest(), getAttackTypeName());
		clone.setOriginalResponse(originalResponse);
		clone.setPayload(payload);
		clone.setOriginalPayload(getOriginalPayload());
		clone.setReplaceType(getReplaceType());

		if (getReplaceType() == REPLACE_TYPE.PATH || getReplaceType() == REPLACE_TYPE.QUERY) {
			
				String pathWithPayload = replaceWithPayload(modifiedRequest.path(),payload);
				
				clone.setModifiedRequest(modifiedRequest.withPath(pathWithPayload));

			} else if (getReplaceType() == REPLACE_TYPE.BODY) {
				String bodyWithPayload = replaceWithPayload(modifiedRequest.bodyToString(),payload);
				
				clone.setModifiedRequest(modifiedRequest.withBody(bodyWithPayload));
				
			} else if (getReplaceType() == REPLACE_TYPE.HEADER_VALUE) {

				for(HttpHeader header : modifiedRequest.headers()) {
					String maybeReplacedHeader = replaceWithPayload(header.value(),payload);
					if(!maybeReplacedHeader.equals("")) {
						clone.setModifiedRequest(modifiedRequest.withHeader(header.name(), maybeReplacedHeader));
					}
				}
			}
		

		return clone;
	}

	// looks for the placeholders and replace everyhting between them with the
	// payload
	private String replaceWithPayload(String original, String payload) {

		int firstPlaceHolder = original.indexOf(matchPlaceHolder);
		int secondPlaceHolder = -1;
		
		if (firstPlaceHolder >= 0) {
			// Find the second occurrence of '§'
			secondPlaceHolder = original.indexOf(matchPlaceHolder, firstPlaceHolder + 1);
		}

		if (secondPlaceHolder >= 0) {
			return original.substring(0, firstPlaceHolder) + payload + original.substring(secondPlaceHolder + 1);
		}
		return "";
	}

	public HttpRequest getOriginalRequest() {
		return originalRequest;
	}

	public void setOriginalRequest(HttpRequest originalRequest) {
		this.originalRequest = originalRequest;
	}

	public String toString() {
		return "";
	}

	public HttpRequest getModifiedRequest() {
		return modifiedRequest;
	}

	public void setModifiedRequest(HttpRequest modifiedRequest) {
		this.modifiedRequest = modifiedRequest;
	}

	public AttackTypeName getAttackTypeName() {
		return attackTypeName;
	}

	// two candidates are equals if their modified url, all header values and body are the same
	@Override
	public boolean equals(Object obj) {
		AttackCandidate otherCandidate = (AttackCandidate) obj;
		if (this.getModifiedRequest().url().equals(otherCandidate.getModifiedRequest().url())
				&& this.getModifiedRequest().body().equals(otherCandidate.getModifiedRequest().body())) {
			
			for(HttpHeader header : getModifiedRequest().headers()) {
				if(otherCandidate.modifiedRequest.hasHeader(header.name())) {
					if(!header.value().equals(otherCandidate.modifiedRequest.headerValue(header.name()))) {
						return false;
					} else {
						//header exactly matches, go to the next one
						continue;
					}
				}
				return false;
			}
			return true;
		}
		return false;
	}

	public boolean isEnabled() {
		return enabled;
	}

	public String isEnabledAsString() {
		if (this.enabled) {
			return "true";
		}
		return "false";
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	public HttpResponse getOriginalResponse() {
		return originalResponse;
	}

	public void setOriginalResponse(HttpResponse originalResponse) {
		this.originalResponse = originalResponse;
	}

	public String getPayload() {
		return payload;
	}

	public void setPayload(String payload) {
		this.payload = payload;
	}

	public HttpResponse getAttackResponse() {
		return attackResponse;
	}

	public void setAttackResponse(HttpResponse attackResponse) {
		this.attackResponse = attackResponse;
	}

	public String getResultStatus() {
		return resultStatus;
	}

	public void setResultStatus(String resultStatus) {
		this.resultStatus = resultStatus;
	}

	public String getOriginalPayload() {
		return replacedPayload;
	}

	public void setOriginalPayload(String replacedString) {
		this.replacedPayload = replacedString;
	}

	public REPLACE_TYPE getReplaceType() {
		return replaceType;
	}

	public void setReplaceType(REPLACE_TYPE replaceType) {
		this.replaceType = replaceType;
	}

}
