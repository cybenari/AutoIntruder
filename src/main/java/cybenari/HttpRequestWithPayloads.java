package cybenari;

import java.util.ArrayList;

import burp.api.montoya.http.message.requests.HttpRequest;

//a wrapper for HttpRequest that also holds payloads
public class HttpRequestWithPayloads {

	HttpRequest httpRequestWithPosition;
	ArrayList<String> payloads;

	public HttpRequestWithPayloads(HttpRequest httpRequestWithPosition) {
		this.httpRequestWithPosition = httpRequestWithPosition;
		payloads = new ArrayList<>();
	}

	public ArrayList<String> getPayloads() {
		return this.payloads;
	}

	public void setPayloads(ArrayList<String> payloads) {
		this.payloads = payloads;
	}

	public void addPayloads(String payload) {
		this.payloads.add(payload);
	}

	public HttpRequest getHttpRequestWithPosition() {
		return this.httpRequestWithPosition;

	}


}
