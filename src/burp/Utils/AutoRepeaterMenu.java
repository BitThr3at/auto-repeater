package burp.Utils;

import burp.AutoRepeater;
import burp.BurpExtender;
import burp.IExtensionStateListener;
import burp.Logs.LogEntry;
import burp.Logs.LogManager;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.util.ArrayList;

public class AutoRepeaterMenu implements Runnable, IExtensionStateListener {
  private final JRootPane rootPane;
  private static java.util.List<AutoRepeater> autoRepeaters;

  private static JMenu autoRepeaterJMenu;
  public static boolean sendRequestsToPassiveScanner;
  public static boolean addRequestsToSiteMap;

  public AutoRepeaterMenu(JRootPane rootPane) {
    this.rootPane = rootPane;
    autoRepeaters = BurpExtender.getAutoRepeaters();
    BurpExtender.getCallbacks().registerExtensionStateListener(this);
  }

  /**
   * Action listener for import settings menu
   */
  class ImportSettingListener implements ActionListener {

    @Override
    public void actionPerformed(ActionEvent e) {
      final JFileChooser importPathChooser = new JFileChooser();
      int returnVal = importPathChooser.showOpenDialog(rootPane);
      if (returnVal != JFileChooser.APPROVE_OPTION) {
        BurpExtender.getCallbacks().printOutput("Cannot open a file dialog for importing settings.");
        return;
      }
      File file = importPathChooser.getSelectedFile();
      String fileData = Utils.readFile(file);
      if (fileData.equals("")) {
        // file empty
        return;
      }
      BurpExtender.initializeFromSave(fileData);
    }
  }

  /**
   * Action listener for export settings menu.
   */
  class ExportSettingListener implements ActionListener {
    @Override
    public void actionPerformed(ActionEvent e) {
      final JFileChooser exportPathChooser = new JFileChooser();
      int returnVal = exportPathChooser.showSaveDialog(rootPane);
      if (returnVal != JFileChooser.APPROVE_OPTION) {
        BurpExtender.getCallbacks().printOutput("Cannot open a file dialog for exporting settings.");
        return;
      }
      File file = exportPathChooser.getSelectedFile();
      try (PrintWriter out = new PrintWriter(file.getAbsolutePath())) {
        out.println(BurpExtender.exportSave());
      } catch (FileNotFoundException error) {
        error.printStackTrace();
      }
    }
  }

  /**
   * Action listener for export logs menu.
   */
  class ExportLogsListener implements ActionListener {

    @Override
    public void actionPerformed(ActionEvent e) {
      Object[] options = {"Export", "Cancel"};
      final String[] EXPORT_OPTIONS = {"CSV", "JSON"};
      final String[] EXPORT_WHICH_OPTIONS = {"All Logs", "Selected Logs"};
      final String[] EXPORT_VALUE_OPTIONS = {"Log Entry", "Log Entry + Full HTTP Request"};

      final JComboBox<String> exportTypeComboBox = new JComboBox<>(EXPORT_OPTIONS);
      final JComboBox<String> exportWhichComboBox = new JComboBox<>(EXPORT_WHICH_OPTIONS);
      final JComboBox<String> exportValueComboBox = new JComboBox<>(EXPORT_VALUE_OPTIONS);

      final JFileChooser exportLogsPathChooser = new JFileChooser();

      JPanel exportLogsPanel = new JPanel();
      exportLogsPanel.setLayout(new BoxLayout(exportLogsPanel, BoxLayout.PAGE_AXIS));
      exportLogsPanel.add(exportWhichComboBox);
      exportLogsPanel.add(exportValueComboBox);
      exportLogsPanel.add(exportTypeComboBox);
      JPanel buttonPanel = new JPanel();
      exportLogsPanel.add(buttonPanel);

      int option = JOptionPane.showOptionDialog(rootPane, exportLogsPanel,
          "Export Logs", JOptionPane.DEFAULT_OPTION, JOptionPane.QUESTION_MESSAGE, null, options, options[0]);
      if (option == 1) {
        return;
      }
      int returnVal = exportLogsPathChooser.showSaveDialog(rootPane);
      if (returnVal != JFileChooser.APPROVE_OPTION) {
        BurpExtender.getCallbacks().printOutput("Cannot open a file dialog for exporting logs.");
        return;
      }
      AutoRepeater autoRepeater = BurpExtender.getAutoRepeater();
      LogManager logManager = autoRepeater.getLogManager();
      File file = exportLogsPathChooser.getSelectedFile();
      final ArrayList<LogEntry> logEntries = new ArrayList<>();
      // collect relevant entries
      if ((exportWhichComboBox.getSelectedItem()).equals("All Logs")) {
        logEntries.addAll(autoRepeater.getLogTableModel().getLog());
      } else if ((exportWhichComboBox.getSelectedItem()).equals("Selected Logs")) {
        int[] selectedRows = autoRepeater.getLogTable().getSelectedRows();
        for (int row : selectedRows) {
          logEntries.add(logManager.getLogEntry(autoRepeater.getLogTable().convertRowIndexToModel(row)));
        }
      }
      // determine if whole request should be exported or just the log contents
      final boolean exportFullHttp = !((exportValueComboBox.getSelectedItem()).equals("Log Entry"));
      final boolean exportCsv = (exportTypeComboBox.getSelectedItem()).equals("CSV");

      // Serialising the log reads every request and response back from disk, so it must not run on
      // the event thread: exporting a few hundred entries froze Burp until it finished.
      Thread exportThread = new Thread(() -> {
        try (PrintWriter out = new PrintWriter(file.getAbsolutePath())) {
          out.println(exportCsv
              ? Utils.exportLogEntriesToCsv(logEntries, exportFullHttp)
              : Utils.exportLogEntriesToJson(logEntries, exportFullHttp));
          BurpExtender.getCallbacks().printOutput(
              "Exported " + logEntries.size() + " log entries to " + file.getAbsolutePath());
        } catch (FileNotFoundException error) {
          BurpExtender.getCallbacks().printError(
              "Could not write " + file.getAbsolutePath() + ": " + error.getMessage());
        }
      }, "AutoRepeater-export");
      exportThread.setDaemon(true);
      exportThread.start();
    }
  }

  @Override
  public void extensionUnloaded() {
    // unregister menu
    JMenuBar burpMenuBar = rootPane.getJMenuBar();
    BurpExtender.getCallbacks().printOutput("Unregistering menu");
    burpMenuBar.remove(autoRepeaterJMenu);
    burpMenuBar.repaint();
  }

  @Override
  public void run() {
    JMenuBar burpJMenuBar = rootPane.getJMenuBar();
    autoRepeaterJMenu = new JMenu("AutoRepeater");
    // initialize menu items and add action listeners
    JCheckBoxMenuItem toggleSendRequestsToPassiveScanner = new JCheckBoxMenuItem("Send Requests To Passive Scanner");
    toggleSendRequestsToPassiveScanner.addActionListener(l ->
        sendRequestsToPassiveScanner = toggleSendRequestsToPassiveScanner.getState());

    JCheckBoxMenuItem toggleAddRequestsToSiteMap = new JCheckBoxMenuItem("Add Requests To Site Map");
    toggleAddRequestsToSiteMap.addActionListener(l ->
        addRequestsToSiteMap = toggleAddRequestsToSiteMap.getState());

    JMenuItem showImportMenu = new JMenuItem("Import Settings");
    showImportMenu.addActionListener(new ImportSettingListener());

    JMenuItem showExportMenu = new JMenuItem("Export Settings");
    showExportMenu.addActionListener(new ExportSettingListener());

    JMenuItem showExportLogsMenu = new JMenuItem("Export Logs");
    showExportLogsMenu.addActionListener(new ExportLogsListener());
    // add menu items to the menu
    autoRepeaterJMenu.add(toggleAddRequestsToSiteMap);
    autoRepeaterJMenu.add(toggleSendRequestsToPassiveScanner);
    autoRepeaterJMenu.addSeparator();
    autoRepeaterJMenu.add(showImportMenu);
    autoRepeaterJMenu.add(showExportMenu);
    autoRepeaterJMenu.add(showExportLogsMenu);
    // add menu to menu bar
    burpJMenuBar.add(autoRepeaterJMenu, burpJMenuBar.getMenuCount() - 2);
  }
}
