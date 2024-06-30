package cybenari.models;

import burp.api.montoya.logging.Logging;
import cybenari.AttackCandidate;

import javax.swing.table.AbstractTableModel;

import java.util.ArrayList;
import java.util.List;

public class RequestsTableModel extends MyAbstractTableModel {
	private List<AttackCandidate> log;
	private final Logging logging;

	public RequestsTableModel(Logging logging) {
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
		return 7;
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
			return "Code";
		case 4:
			return "Enabled";
		case 5:
			return "Original Payload";
		case 6:
			return "Change Type";
		default:
			return "";
		}
	}

	@Override
	public synchronized Object getValueAt(int rowIndex, int columnIndex) {

		if (rowIndex < log.size()) {

			AttackCandidate candidate = log.get(rowIndex);

			if (candidate != null) {
				switch (columnIndex) {
				case 0:
					return rowIndex;
				case 1:
					return candidate.getOriginalRequest().url();
				case 2:
					return candidate.getOriginalRequest().method();
				case 3:
					if (candidate.getOriginalResponse() != null) {
						return candidate.getOriginalResponse().statusCode();
					}
					return "";
				case 4:
					return candidate.isEnabledAsString();
				case 5:
					if (candidate.getOriginalPayload() != null) {
						return candidate.getOriginalPayload();
					}
					return "";
				case 6:
					return candidate.getReplaceType().toString();
				default:
					return "";
				}
			}
		}
		return "";
	}

	public synchronized void add(AttackCandidate candidate) {
		int index = log.size();
		if (!log.contains(candidate)) {
			log.add(candidate);
			fireTableRowsInserted(index, index);
		}
	}

	public synchronized AttackCandidate get(int rowIndex) {
		return log.get(rowIndex);
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

	public void removeAll() {
		int rowCount = getRowCount();
		log.clear();
		fireTableRowsDeleted(0, rowCount - 1);
		this.log = new ArrayList<>();

	}

	public void removeAt(int modelRow) {
		log.remove(modelRow);

	}
}
