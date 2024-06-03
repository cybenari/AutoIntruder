package cybenari.models;

import java.util.ArrayList;

import javax.swing.table.AbstractTableModel;

import cybenari.AttackCandidate;
import cybenari.rules.*;

public class RulesTableModel extends AbstractTableModel {

	private ArrayList<AbstractRule> rules;

	public RulesTableModel() {
		this.rules = new ArrayList<AbstractRule>();
	}

	@Override
	public int getRowCount() {

		return rules.size();
	}

	@Override
	public String getColumnName(int column) {
		switch (column) {
		case 0:
			return "#";
		case 1:
			return "Enabled";
		case 2:
			return "Operator";
		case 3:
			return "Type";
		case 4:
			return "Pattern";
		default:
			return "";
		}
	}

	@Override
	public int getColumnCount() {
		// TODO Auto-generated method stub
		return 5;
	}

	@Override
	public Object getValueAt(int rowIndex, int columnIndex) {
		
		if (rowIndex < rules.size()) {
			
			AbstractRule rule = rules.get(rowIndex);
			switch (columnIndex) {
			case 0:
				return rowIndex;
			case 1:
				if (rule.isEnabled()) {
					return "True";
				}
				;
				return "False";
			case 2:
				return rule.getOperation().toString();
			case 3:
				return rule.getMatchType().toString();
			case 4:
				return rule.getMatchPattern();
			default:
				return "";

			}
		}
		return "";
	}

	public synchronized void add(AbstractRule rule) {
		int index = rules.size();
		rules.add(rule);
		fireTableRowsInserted(index, index);
	}

	public ArrayList<AbstractRule> getAll() {
		
		return this.rules;
	}

	public void removeAt(int i) {
		rules.remove(i);
		fireTableRowsDeleted(i,i);
		
	}

}
