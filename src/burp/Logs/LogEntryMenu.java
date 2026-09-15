package burp.Logs;

import burp.AutoRepeater.LogTable;
import burp.BurpExtender;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import javax.swing.AbstractAction;
import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;

/**
 * Right click menu for the log table.
 *
 * Originally this only offered "Clear Logs"; the entry under the cursor was looked up but never
 * used. It now acts on the row that was clicked.
 */
public class LogEntryMenu extends JPopupMenu {

  public LogEntryMenu(final LogManager logManager, final LogTable logTable, final int row,
      final int col) {
    final LogTableModel logTableModel = logManager.getLogTableModel();
    final LogEntry entry = logTableModel.getLogEntry(row);
    final String columnName = logTableModel.getColumnName(col);
    final Object columnValue = logTableModel.getValueAt(row, col);

    add(new JMenuItem(new AbstractAction("Send request to Repeater") {
      @Override
      public void actionPerformed(ActionEvent actionEvent) {
        BurpExtender.getCallbacks().sendToRepeater(
            entry.getModifiedRequestResponse().getHttpService().getHost(),
            entry.getModifiedRequestResponse().getHttpService().getPort(),
            "https".equals(entry.getModifiedRequestResponse().getHttpService().getProtocol()),
            entry.getModifiedRequestResponse().getRequest(),
            "AutoRepeater " + entry.getRequestResponseId());
      }
    }));

    add(new JMenuItem(new AbstractAction("Copy URL") {
      @Override
      public void actionPerformed(ActionEvent actionEvent) {
        copyToClipboard(entry.getModifiedUrlString());
      }
    }));

    add(new JMenuItem(new AbstractAction("Copy " + columnName) {
      @Override
      public void actionPerformed(ActionEvent actionEvent) {
        copyToClipboard(columnValue == null ? "" : columnValue.toString());
      }
    }));

    addSeparator();

    add(new JMenuItem(new AbstractAction("Clear Logs") {
      @Override
      public void actionPerformed(ActionEvent actionEvent) {
        logTableModel.clearLogs();
        logTable.revalidate();
      }
    }));
  }

  private static void copyToClipboard(String value) {
    Toolkit.getDefaultToolkit().getSystemClipboard()
        .setContents(new StringSelection(value), null);
  }
}
