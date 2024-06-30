package cybenari.models;

import burp.api.montoya.logging.Logging;
import cybenari.AttackCandidate;
import java.util.ArrayList;
import java.util.List;

public class ResultsTableModel extends MyAbstractTableModel {
	private List<AttackCandidate> log;
	private final Logging logging;
	private int maxTableSize = 20000;

	public ResultsTableModel(Logging logging) {
		this.log = new ArrayList<>();
		this.logging = logging;
	}

	public boolean contains(AttackCandidate candidate) {
		boolean containsResult = this.log.contains(candidate);

		if (containsResult) {
			logging.logToOutput("Found duplicate of attack candidate in the table... droping it. "
					+ candidate.getOriginalRequest().url());
		}
		return containsResult;
	}

	@Override
	public synchronized int getRowCount() {
		return log.size();
	}

	@Override
	public int getColumnCount() {
		return 12;
	}

	@Override
	public String getColumnName(int column) {
		switch (column) {
		case 0:
			return "#";
		case 1:
			return "URL";
		case 2:
			return "Method";
		case 3:
			return "New Payload";
		case 4:
			return "Original Payload";
		case 5:
			return "Original Status Code";
		case 6:
			return "Modified Status Code";
		case 7:
			return "Enabled";
		case 8:
			return "Original response size";
		case 9:
			return "Modified response size";
		case 10:
			return "Execution Status";
		case 11:
			return "Change Type";
		default:
			return "";
		}
	}

	@Override
	public synchronized Object getValueAt(int rowIndex, int columnIndex) {
		AttackCandidate candidate = log.get(rowIndex);

		switch (columnIndex) {
		case 0:
			return rowIndex;
		case 1:
			return candidate.getOriginalRequest().url();
		case 2:
			return candidate.getOriginalRequest().method();
		case 3:
			return candidate.getPayload();
		case 4:
			if (candidate.getOriginalPayload() != null) {
				return candidate.getOriginalPayload();
			}
			return "";

		case 5:
			if (candidate.getOriginalResponse() != null) {
				return candidate.getOriginalResponse().statusCode();
			} else {
				return "";
			}
		case 6:
			if (candidate.getAttackResponse() != null) {
				return candidate.getAttackResponse().statusCode();
			} else {
				return "";
			}
		case 7:
			return candidate.isEnabledAsString();
		case 8:
			if (candidate.getOriginalResponse() != null
					&& candidate.getOriginalResponse().headerValue("Content-Length") != null) {
				return candidate.getOriginalResponse().headerValue("Content-Length");
			}
			return "";
		case 9:

			if (candidate.getAttackResponse() != null
					&& candidate.getAttackResponse().headerValue("Content-Length") != null) {
				return candidate.getAttackResponse().headerValue("Content-Length");
			}
			return "";
		case 10:
			return candidate.getResultStatus();
		case 11:
			return candidate.getReplaceType().toString();
		default:
			return "";
		}
	}

	public synchronized void add(AttackCandidate candidate) {
		if (log.size() < this.maxTableSize) {
			int index = log.size();
			log.add(candidate);
			fireTableRowsInserted(index, index);
		} else {
			logging.logToError("max results table size reached! not adding new candidates");
		}
	}

	public synchronized AttackCandidate get(int rowIndex) {
		return log.get(rowIndex);
	}

	public void removeAll() {
		int rowCount = getRowCount();
		log.clear();
		fireTableRowsDeleted(0, rowCount - 1);
		this.log = new ArrayList<>();

	}

	public ArrayList<AttackCandidate> getAll() {
		return (ArrayList<AttackCandidate>) this.log;
	}

	public ArrayList<AttackCandidate> getAllEnabled() {
		ArrayList<AttackCandidate> enabledCandidates = new ArrayList<>();

		for (AttackCandidate candidate : this.log) {
			if (candidate.isEnabled()) {
				enabledCandidates.add(candidate);
			}
		}
		return enabledCandidates;
	}

	public void removeAt(int modelRow) {
		log.remove(modelRow);

	}
}
