package cybenari.models;

import javax.swing.table.AbstractTableModel;

import cybenari.AttackCandidate;

public abstract class MyAbstractTableModel extends AbstractTableModel{

	public abstract AttackCandidate get(int rowIndex);
	
	public abstract void removeAll();

	public abstract void removeAt(int i);
}
