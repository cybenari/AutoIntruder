package cybenari;

import java.util.ArrayList;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import burp.api.montoya.http.message.params.ParsedHttpParameter;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;

public class PayloadScraper {

	private ArrayList<ProxyHttpRequestResponse> history;
	private String defaultPayloadPattern = "[0-9]{10}";
	
	
	private Pattern payloadPattern;
	private boolean inScopeOnly = true;

	public PayloadScraper() {
		this.history = new ArrayList<>();
		this.setPayloadPattern(Pattern.compile(defaultPayloadPattern));
	}

	public static Properties getRegexOptions() {
		Properties properties = new Properties();
		
		properties.setProperty("UUID", "[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[1-5][a-fA-F0-9]{3}-[89abAB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}");
        properties.setProperty("Email", "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}");
        properties.setProperty("JWT","eyJ[a-zA-Z0-9-_]+\\.[a-zA-Z0-9-_]+\\.[a-zA-Z0-9-_]+");
        properties.setProperty("IP Address","\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b");
        properties.setProperty("URL","https?:\\/\\/(?:www\\.)?[a-zA-Z0-9./?=&-_]+");
        properties.setProperty("Date (YYYY-MM-DD)","\\d{4}-\\d{2}-\\d{2}");
        properties.setProperty("Base64","(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)");
        return properties;
		
	}
	public ArrayList<ProxyHttpRequestResponse> getHistory() {
		return history;
	}

	public void setHistory(ArrayList<ProxyHttpRequestResponse> history) {
		this.history = history;
	}

	public Pattern getPayloadPattern() {
		return payloadPattern;
	}

	public void setPayloadPattern(Pattern payloadPattern) {
		this.payloadPattern = payloadPattern;
	}

	public ArrayList<String> findAllUniquePayloads() {

		ArrayList<String> foundPayloads = new ArrayList<>();

		for (ProxyHttpRequestResponse requestResponse : getHistory()) {

			if (requestResponse != null) {
				// ignore out of scope params if the configuration defines it.
				if (!requestResponse.request().isInScope() && isInScopeOnly()) {
					continue;
				}
				/*
				// gets all matching param values from requests
				for (ParsedHttpParameter parameter : requestResponse.request().parameters()) {
					Matcher matcher = getPayloadPattern().matcher(parameter.value());
					if (matcher.matches()) {
						if (!foundPayloads.contains(parameter.value())) {
							foundPayloads.add(parameter.value());
						}
					}
				}
				*/
				
				Matcher matcher = getPayloadPattern().matcher(requestResponse.request().bodyToString());
				while (matcher.find()) {
					if (!foundPayloads.contains(matcher.group())) {
						foundPayloads.add(matcher.group());
					}

				}
				
				if (requestResponse.response() != null) {
					// gets all matches in responses
					matcher = getPayloadPattern().matcher(requestResponse.response().toString());

					while (matcher.find()) {
						if (!foundPayloads.contains(matcher.group())) {
							foundPayloads.add(matcher.group());
						}

					}
				}

			}
		}

		return foundPayloads;
	}

	public boolean isInScopeOnly() {
		return inScopeOnly;
	}

	public void setInScopeOnly(boolean inScopeOnly) {
		this.inScopeOnly = inScopeOnly;
	}

}
