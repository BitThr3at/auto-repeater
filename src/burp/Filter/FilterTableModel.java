package burp.Filter;

import burp.Conditions.Condition;
import burp.Conditions.ConditionTableModel;
import burp.Logs.LogEntry;
import java.util.ArrayList;
import java.util.stream.Collectors;

public class FilterTableModel extends ConditionTableModel {

  private final static String[] columnNames = {
      "Enabled",
      "Boolean Operator",
      "Original Or Modified",
      "Match Type",
      "Match Relationship",
      "Match Condition"
  };

  /**
   * Evaluated once per log entry on every insert and on every re-filter, so it walks the conditions
   * directly instead of building two intermediate lists and two streams per call.
   */
  public boolean check(LogEntry logEntry) {
    if (getConditions().isEmpty()) {
      return true;
    }
    // An "Or" filter matching is enough; "And"/"" filters must all match. As before, a set with no
    // enabled "And" filters counts as matching.
    boolean andMatch = true;
    ArrayList<Condition> conditions = getConditions();
    // Indexed loop: filters can be edited while logs are being filtered.
    for (int i = 0; i < conditions.size(); i++) {
      Condition condition = conditions.get(i);
      if (!condition.isEnabled()) {
        continue;
      }
      Filter filter = (Filter) condition;
      if ("Or".equals(filter.getBooleanOperator())) {
        if (filter.checkCondition(logEntry)) {
          return true;
        }
      } else if (andMatch && !filter.checkCondition(logEntry)) {
        andMatch = false;
      }
    }
    return andMatch;
  }

  public ArrayList<Filter> getFilters() {
    return getConditions().stream()
        .map(x -> (Filter)x)
        .collect(Collectors.toCollection(ArrayList::new));
  }

  public Filter get(int index) { return (Filter)super.get(index); }

  @Override
  public String getColumnName(int col) {
    return columnNames[col];
  }

  @Override
  public int getColumnCount() {
    return columnNames.length;
  }

  @Override
  public Object getValueAt(int row, int col) {
    Filter filter = get(row);
    switch (col) {
      case 0:
        return filter.isEnabled();
      case 1:
        return filter.getBooleanOperator();
      case 2:
        return filter.getOriginalOrModified();
      case 3:
        return filter.getMatchType();
      case 4:
        return filter.getMatchRelationship();
      case 5:
        return filter.getMatchCondition();
      default:
        throw new IllegalStateException("getValueAt not defined for "+Integer.toString(col));
    }
  }

  @Override
  public void setValueAt(Object value, int row, int col) {
    Filter filter = get(row);
    switch (col) {
      case 0:
        filter.setEnabled((Boolean) value);
        break;
      case 1:
        filter.setBooleanOperator((String) value);
        break;
      case 2:
        filter.setOriginalOrModified((String) value);
        break;
      case 3:
        filter.setMatchType((String) value);
        break;
      case 4:
        filter.setMatchRelationship((String) value);
        break;
      case 5:
        filter.setMatchCondition((String) value);
        break;
      default:
        throw new IllegalStateException("setValueAt not defined for "+Integer.toString(col));
    }
    update(row, filter);
    fireTableCellUpdated(row, col);
  }
}
