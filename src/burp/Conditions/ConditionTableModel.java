package burp.Conditions;

import burp.IHttpRequestResponse;
import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;

public class ConditionTableModel extends AbstractTableModel {

  private final static String[] columnNames = {
      "Enabled",
      "Boolean Operator",
      "Match Type",
      "Match Relationship",
      "Match Condition"
  };

  private ArrayList<Condition> conditions;

  // Setting default conditions
  public ConditionTableModel() {
    conditions = new ArrayList<>();
  }

  public void add(Condition condition) { conditions.add(condition); }

  public void update(int index, Condition condition) {
    if (index == 0) {
      condition.setBooleanOperator("");
    }
    conditions.set(index, condition);
  }

  /**
   * Runs for every message Burp sees, so it walks the conditions once and stops as soon as the
   * result is known rather than building two streams per call.
   */
  public boolean check(int toolFlag, IHttpRequestResponse messageInfo) {
    if (conditions.isEmpty()) {
      return false;
    }
    // An "Or" condition matching is enough; "And"/"" conditions must all match. As before, a set
    // with no enabled "And" conditions counts as matching.
    boolean andMatch = true;
    // Indexed loop: this runs on Burp's HTTP threads while the table may be edited on the event
    // thread, and an iterator would throw ConcurrentModificationException.
    for (int i = 0; i < conditions.size(); i++) {
      Condition condition = conditions.get(i);
      if (!condition.isEnabled()) {
        continue;
      }
      if ("Or".equals(condition.getBooleanOperator())) {
        if (condition.checkCondition(toolFlag, messageInfo)) {
          return true;
        }
      } else if (andMatch && !condition.checkCondition(toolFlag, messageInfo)) {
        andMatch = false;
      }
    }
    return andMatch;
  }

  public ArrayList<Condition> getConditions() {
    return conditions;
  }

  public Condition get(int conditionIndex) {
    return conditions.get(conditionIndex);
  }

  public void remove(int index) {
    if (index != 0) { conditions.remove(index); }
  }

  public void clear() {
    conditions.clear();
  }

  @Override
  public int getColumnCount() {
    return columnNames.length;
  }

  @Override
  public int getRowCount() {
    return conditions.size();
  }

  @Override
  public String getColumnName(int col) {
    return columnNames[col];
  }

  @Override
  public Object getValueAt(int row, int col) {
    Condition tempCondition = conditions.get(row);
    switch (col) {
      case 0:
        return tempCondition.isEnabled();
      case 1:
        return tempCondition.getBooleanOperator();
      case 2:
        return tempCondition.getMatchType();
      case 3:
        return tempCondition.getMatchRelationship();
      case 4:
        return tempCondition.getMatchCondition();
      default:
        throw new IllegalStateException("getValueAt not defined for "+Integer.toString(col));
    }
  }

  @Override
  public Class getColumnClass(int column) {
    return (getValueAt(0, column).getClass());
  }

  @Override
  public boolean isCellEditable(int row, int column) {
    return (getColumnName(column).equals("Enabled") && row != 0);
  }

  @Override
  public void setValueAt(Object value, int row, int col) {
    Condition tempCondition = conditions.get(row);
    switch (col) {
      case 0:
        tempCondition.setEnabled((Boolean) value);
        break;
      case 1:
        tempCondition.setBooleanOperator((String) value);
        break;
      case 2:
        tempCondition.setMatchType((String) value);
        break;
      case 3:
        tempCondition.setMatchRelationship((String) value);
        break;
      default:
        tempCondition.setMatchCondition((String) value);
        break;
    }
    conditions.set(row, tempCondition);
  }
}
