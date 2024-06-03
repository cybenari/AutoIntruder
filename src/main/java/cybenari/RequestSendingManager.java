package cybenari;

import java.util.ArrayList;

import burp.api.montoya.MontoyaApi;
import cybenari.models.ResultsTableModel;

public class RequestSendingManager {

	private int numberOfThreads = 2;

	private final int maxNumberOfThreads = 20;
	private ResultsTableModel resultsTableModel;
	private MontoyaApi api;
	private long requestDelay = 0;
	private ArrayList<HttpRequester> requesterThreads;

	public RequestSendingManager(ResultsTableModel resultsTableModel, MontoyaApi api) {
		this.resultsTableModel = resultsTableModel;
		this.api = api;
		requesterThreads = new ArrayList<HttpRequester>();
	}

	public int getNumberOfThreads() {
		return numberOfThreads;
	}

	public void setNumberOfThreads(int numberOfThreads) {
		if (numberOfThreads > getMaxNumberOfThreads()) {
			numberOfThreads = getMaxNumberOfThreads();
		} else {
			this.numberOfThreads = numberOfThreads;
		}
	}

	public void stopAllThreads() {

		for (HttpRequester thread : this.requesterThreads) {
			thread.stopExecution();
		}
	}

	public int getMaxNumberOfThreads() {
		return maxNumberOfThreads;
	}

	public long getRequestDelay() {
		return this.requestDelay;
	}

	public void setRequestDelay(long requestDelay) {
		this.requestDelay = requestDelay;
	}

	public void executeAll() {

		resetAllAttackResults();
		assignCandidatesToThreads();
		
		for(HttpRequester thread : requesterThreads) {
			thread.run();
		}

		for (HttpRequester thread : requesterThreads) {
			
				thread.join();
			
		}

	

	}

	private void assignCandidatesToThreads() {
		ArrayList<AttackCandidate> enabledCandidates = resultsTableModel.getAllEnabled();

		int numofCandidates = enabledCandidates.size();
		int chunkSize = (numofCandidates + numberOfThreads - 1) / numberOfThreads; // Calculate the size of each chunk

		for (int i = 0; i < numberOfThreads; i++) {
			int start = i * chunkSize;
			int end = Math.min(start + chunkSize, numofCandidates);

			if (start >= numofCandidates)
				break; // No more URLs to process

			ArrayList<AttackCandidate> candidatesForThread = new ArrayList<>();
			for (int j = start; j < end; j++) {
				candidatesForThread.add(enabledCandidates.get(j));
			}
			HttpRequester httpRequester = new HttpRequester(candidatesForThread, this.api, this.requestDelay); // auto
																												// starts
			requesterThreads.add(httpRequester);
		}
	}

	private void resetAllAttackResults() {
		for (AttackCandidate candidate : resultsTableModel.getAll()) {
			candidate.setAttackResponse(null);
			candidate.setResultStatus("Not Executed");
		}
	}

}
