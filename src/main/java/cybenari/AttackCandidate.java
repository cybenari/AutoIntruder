package cybenari;

import java.util.ArrayList;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import cybenari.AbstractAttackType.AttackTypeName;

public class AttackCandidate {

	private HttpRequest originalRequest;
	private HttpRequest modifiedRequest;
	private HttpResponse originalResponse;
	private HttpResponse attackResponse;
	private boolean enabled = true;
	private String resultStatus = "Not executed";
	private String payload;
	private String matchPlaceHolder = "§";
	private String replacedPayload = "";

	// private ArrayList<HttpRequestWithPayloads> requestWithPayloads;
	private AttackTypeName attackTypeName;

	public AttackCandidate(HttpRequest originalRequest, AttackTypeName attackTypeName) {
		this.setOriginalRequest(originalRequest);

		this.attackTypeName = attackTypeName;
		// this.requestWithPayloads = new ArrayList<>();
	}

	//creates a clone of the attack candidates and replaces the place holders with payload
	public AttackCandidate cloneWithPayload(String payload) {
		AttackCandidate clone = new AttackCandidate(getOriginalRequest(), getAttackTypeName());
		clone.setOriginalResponse(originalResponse);
		clone.setPayload(payload);
		clone.setOriginalPayload(getOriginalPayload());

		// is placeholder in path or body?
		if (modifiedRequest.path().indexOf(matchPlaceHolder) > 0) {
			// Find the first occurrence of 'X'
			int firstPlaceHolder = modifiedRequest.path().indexOf(matchPlaceHolder);
			// Find the second occurrence of 'X'
			int secondPlaceHolder = modifiedRequest.path().indexOf(matchPlaceHolder, firstPlaceHolder + 1);
		
			String pathWithPayload = modifiedRequest.path().substring(0, firstPlaceHolder) + payload
					+ modifiedRequest.path().substring(secondPlaceHolder + 1);
			clone.setModifiedRequest(modifiedRequest.withPath(pathWithPayload));

		} else {// placeholder is in the body
			String body = modifiedRequest.bodyToString();
			int firstPlaceHolder = body.indexOf(matchPlaceHolder);
			int secondPlaceHolder = body.indexOf(matchPlaceHolder, firstPlaceHolder + 1);

			
			String bodyWithPayload = body.substring(0, firstPlaceHolder) + payload
					+ body.substring(secondPlaceHolder + 1);
			clone.setModifiedRequest(modifiedRequest.withBody(bodyWithPayload));
		}

		return clone;
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

	// two candidates are equals i their modified url and body are the same
	public boolean equals(AttackCandidate otherCandidate) {
		return (this.getModifiedRequest().url().equals(otherCandidate.getModifiedRequest().url())
				&& this.getModifiedRequest().body().equals(otherCandidate.getModifiedRequest().body()));
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

}
