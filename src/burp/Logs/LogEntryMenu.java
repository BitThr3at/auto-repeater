package burp.Logs;

import burp.AutoRepeater.LogTable;
import burp.BurpExtender;
import burp.Filter.Filters;
import com.google.common.io.Files;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.event.ActionEvent;
import java.net.URL;
import javax.swing.AbstractAction;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPopupMenu;

/**
 * Right click menu for the log table.
 *
 * Originally this only offered "Clear Logs"; the entry under the cursor was looked up but never
 * used. It now acts on the row that was clicked.
 */
public class LogEntryMenu extends JPopupMenu {

  public LogEntryMenu(final LogManager logManager, final Filters filters, final LogTable logTable,
      final int row, final int col) {
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

    final URL url = entry.getModifiedURL();
    JMenuItem filterOut = new JMenuItem(new AbstractAction("Filter out this endpoint") {
      @Override
      public void actionPerformed(ActionEvent actionEvent) {
        filters.excludeEndpoint(url.getProtocol() + "://" + url.getAuthority() + url.getPath());
      }
    });
    filterOut.setEnabled(url != null);
    add(filterOut);

    final String extension = url == null ? "" : Files.getFileExtension(url.getPath());
    JMenuItem filterOutExtension = new JMenuItem(new AbstractAction(
        extension.isEmpty() ? "Filter out this extension" : "Filter out ." + extension + " requests") {
      @Override
      public void actionPerformed(ActionEvent actionEvent) {
        filters.excludeExtension(extension);
      }
    });
    filterOutExtension.setEnabled(!extension.isEmpty());
    add(filterOutExtension);

    add(new JMenuItem(new AbstractAction("Filter to in-scope only") {
      @Override
      public void actionPerformed(ActionEvent actionEvent) {
        filters.filterInScopeOnly();
      }
    }));

    add(new JMenuItem(new AbstractAction("Clear Logs") {
      @Override
      public void actionPerformed(ActionEvent actionEvent) {
        int confirm = JOptionPane.showConfirmDialog(logTable,
            "This will permanently remove every logged request from this tab. Continue?",
            "Clear Logs", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
        if (confirm != JOptionPane.YES_OPTION) {
          return;
        }
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
