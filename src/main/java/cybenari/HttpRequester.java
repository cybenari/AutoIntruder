package cybenari;

import java.util.ArrayList;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.HighlightColor;
import burp.api.montoya.http.message.HttpRequestResponse;

public class HttpRequester implements Runnable {

	private ArrayList<AttackCandidate> candidatesToExecute;
	private MontoyaApi api;
	private boolean stopped;
	private long requestDelay;
	Thread t;

	public HttpRequester(ArrayList<AttackCandidate> candidatesToExecute, MontoyaApi api, long requestDelay) {
		
		
		this.api = api;
		this.candidatesToExecute = candidatesToExecute;
		this.requestDelay = requestDelay;
		this.stopped = false;
		t = new Thread(this);
		t.start();
	}

	@Override
	public void run() {

		for (AttackCandidate candidate : candidatesToExecute) {
			if(!stopped) {
				HttpRequestResponse requestResponse = api.http().sendRequest(candidate.getModifiedRequest());
				candidate.setAttackResponse(requestResponse.response());
				candidate.setResultStatus("Done");
	
				Annotations annotations = requestResponse.annotations();
	
				annotations = annotations.withHighlightColor(HighlightColor.BLUE);

				
				try {
					Thread.sleep(requestDelay);
				} catch (InterruptedException e) {
					
					e.printStackTrace();
				}
			}

		}
	}
	
	public void stopExecution() {
		this.stopped = true;
	}

	public void join() {
		try {
			t.join();
		} catch (InterruptedException e) {
			
			e.printStackTrace();
		}
	}

}
