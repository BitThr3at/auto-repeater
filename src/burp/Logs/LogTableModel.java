package burp.Logs;

import burp.Filter.Filters;
import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class LogTableModel extends AbstractTableModel {

  private final ArrayList<LogEntry> log;
  private ArrayList<LogEntry> filteredLogs;

  public LogTableModel() {
    log = new ArrayList<>();
    filteredLogs = new ArrayList<>();
  }

  public void addLogEntry(LogEntry logEntry, Filters filters) {
    addLogEntries(
        Collections.singletonList(logEntry),
        filters.filter(logEntry)
            ? Collections.singletonList(logEntry)
            : Collections.<LogEntry>emptyList());
  }

  /**
   * Adds a batch of entries with a single table event. One event per entry meant the row sorter
   * re-sorted the whole table for every request. visibleEntries is the subset that passes the log
   * filters, already determined off the event thread.
   */
  public void addLogEntries(List<LogEntry> logEntries, List<LogEntry> visibleEntries) {
    log.addAll(logEntries);
    if (visibleEntries.isEmpty()) {
      return;
    }
    int firstNewRow = filteredLogs.size();
    filteredLogs.addAll(visibleEntries);
    fireTableRowsInserted(firstNewRow, filteredLogs.size() - 1);
  }

  /**
   * Installs a filtered view computed on a background thread. Entries logged while that was running
   * are filtered here; there are only ever a handful of them.
   */
  public void replaceFilteredLogs(
      ArrayList<LogEntry> visibleEntries, int filteredThroughIndex, Filters filters) {
    for (int i = filteredThroughIndex; i < log.size(); i++) {
      LogEntry logEntry = log.get(i);
      if (filters.filter(logEntry)) {
        visibleEntries.add(logEntry);
      }
    }
    filteredLogs = visibleEntries;
    // One event for the whole re-filter instead of one per matching row.
    fireTableDataChanged();
  }

  public void clearLogs() {
    log.clear();
    filteredLogs.clear();
    fireTableDataChanged();
  }

  public LogEntry getLogEntry(int row) {
    //return log.get(row);
    return filteredLogs.get(row);
  }

  public ArrayList<LogEntry> getLog() {
      //return log;
      return log;
  }

  public ArrayList<LogEntry> getFilteredLogs() {
    //return log;
    return filteredLogs;
  }

  public int getLogCount() {
    return log.size();
  }

  @Override
  public int getRowCount() {
    //return log.size();
    return filteredLogs.size();
  }

  @Override
  public int getColumnCount() {
    return 8;
  }

  @Override
  public String getColumnName(int columnIndex) {
    switch (columnIndex) {
      case 0:
        return "#";
      case 1:
        return "Method";
      case 2:
        return "URL";
      case 3:
        return "Orig. Status";
      case 4:
        return "Status";
      case 5:
        return "Orig. Resp. Len.";
      case 6:
        return "Resp. Len.";
      case 7:
        return "Resp. Len. Diff.";
      default:
        return "";
    }
  }

  @Override
  public Class<?> getColumnClass(int columnIndex) {
    switch (columnIndex) {
      case 0:
        return Integer.class;
      case 1:
        return String.class;
      case 2:
        return String.class;
      case 3:
        return Integer.class;
      case 4:
        return Integer.class;
      case 5:
        return Integer.class;
      case 6:
        return Integer.class;
      case 7:
        return Integer.class;
      default:
        return null;
    }
  }

  @Override
  public Object getValueAt(int rowIndex, int columnIndex) {
    //LogEntry logEntry = log.get(rowIndex);
    LogEntry logEntry = filteredLogs.get(rowIndex);
    // ID, Mod Method, Mod URL, Orig Status, Mod Status, Orig Size, Mod Size, Size Difference, Response Distance
    switch (columnIndex) {
      case 0:
        return logEntry.getRequestResponseId();
      case 1:
        return logEntry.getModifiedMethod();
      case 2:
        return logEntry.getModifiedUrlString();
      case 3:
        return logEntry.getOriginalResponseStatus();
      case 4:
        return logEntry.getModifiedResponseStatus();
      case 5:
        return logEntry.getOriginalLength();
      case 6:
        return logEntry.getModifiedLength();
      case 7:
        return logEntry.getLengthDifference();
      default:
        return "";
    }
  }
}
