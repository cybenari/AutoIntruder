package cybenari;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import burp.api.montoya.http.message.requests.HttpRequest;

public abstract class AbstractAttackType {

	
	public enum AttackTypeName {
		UUIDReplacer,
		NeighboringNumbers,
		CustomRule
	}
	
	public abstract AttackTypeName getAttackTypeName();
	
	//checks if the test candidate is suitable for this type of attack
	public abstract boolean isSuitableForAttack(HttpRequest request);

	//prepares the attack
	public abstract ArrayList<AttackCandidate> createAttackCandidates(HttpRequest request);

	
	
	
	private static boolean matchesRegex(String text, String regex) {
		if (text == null || regex == null) {
			return false;
		}
		return text.matches(regex);
	}
	
	protected URL getURLfromRequest(HttpRequest request) {
		URL url = null;
		try {
			url = new URL(request.url());
			return url;
		} catch (MalformedURLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return url;
	}
}
