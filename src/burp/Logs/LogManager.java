package burp.Logs;

import burp.Filter.Filters;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicLong;
import javax.swing.SwingUtilities;
import javax.swing.Timer;

public class LogManager {

  /**
   * New entries arrive on Burp's HTTP threads, potentially hundreds per second. They are queued and
   * flushed to the table model on the event thread in batches so a burst of traffic produces a
   * handful of table events instead of several per request (each of which re-sorts the table).
   */
  private static final int FLUSH_DELAY_MS = 150;

  private final LogTableModel logTableModel;
  /** Entries waiting to be published, with the filter decision already made off the event thread. */
  private final List<LogEntry> pendingEntries = new ArrayList<>();
  private final List<LogEntry> pendingVisibleEntries = new ArrayList<>();
  private final AtomicLong logIdCounter = new AtomicLong();
  private final Timer flushTimer;
  private final ExecutorService filterExecutor = Executors.newSingleThreadExecutor(runnable -> {
    Thread thread = new Thread(runnable, "AutoRepeater-log-filter");
    thread.setDaemon(true);
    return thread;
  });

  public LogManager() {
    logTableModel = new LogTableModel();
    flushTimer = new Timer(FLUSH_DELAY_MS, e -> flush());
    flushTimer.setRepeats(false);
  }

  public int getRowCount() {
    return logTableModel.getRowCount();
  }

  public LogTableModel getLogTableModel() {
    return logTableModel;
  }

  public LogEntry getLogEntry(int row) {
    return logTableModel.getLogEntry(row);
  }

  /** Ids are handed out from the HTTP threads, so they need to be allocated atomically. */
  public long nextLogId() {
    return logIdCounter.incrementAndGet();
  }

  /**
   * Called from Burp's HTTP threads. The filter decision is made here rather than on the event
   * thread because matching a filter reads the request and response back from Burp's temp files.
   */
  public void addEntry(LogEntry logEntry, Filters filters) {
    boolean visible = filters.filter(logEntry);
    synchronized (pendingEntries) {
      pendingEntries.add(logEntry);
      if (visible) {
        pendingVisibleEntries.add(logEntry);
      }
    }
    SwingUtilities.invokeLater(() -> {
      if (!flushTimer.isRunning()) {
        flushTimer.start();
      }
    });
  }

  private void flush() {
    List<LogEntry> entries;
    List<LogEntry> visibleEntries;
    synchronized (pendingEntries) {
      if (pendingEntries.isEmpty()) {
        return;
      }
      entries = new ArrayList<>(pendingEntries);
      visibleEntries = new ArrayList<>(pendingVisibleEntries);
      pendingEntries.clear();
      pendingVisibleEntries.clear();
    }
    logTableModel.addLogEntries(entries, visibleEntries);
  }

  /**
   * Re-applies the log filters. The matching itself runs on a background thread; only the resulting
   * list is handed back to the table model. Doing this inline froze Burp for seconds once a few
   * hundred requests had been logged.
   */
  public void setFilter(Filters filters) {
    final List<LogEntry> snapshot = new ArrayList<>(logTableModel.getLog());
    filterExecutor.submit(() -> {
      ArrayList<LogEntry> visibleEntries = new ArrayList<>(snapshot.size());
      for (LogEntry logEntry : snapshot) {
        if (filters.filter(logEntry)) {
          visibleEntries.add(logEntry);
        }
      }
      SwingUtilities.invokeLater(
          () -> logTableModel.replaceFilteredLogs(visibleEntries, snapshot.size(), filters));
    });
  }

}
