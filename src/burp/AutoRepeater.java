package burp;

import burp.Conditions.Condition;
import burp.Conditions.ConditionTableModel;
import burp.Conditions.Conditions;
import burp.Filter.Filter;
import burp.Filter.FilterTableModel;
import burp.Filter.Filters;
import burp.Highlighter.Highlighter;
import burp.Highlighter.HighlighterTableModel;
import burp.Highlighter.HighlighterUITableModel;
import burp.Highlighter.Highlighters;
import burp.Logs.LogEntry;
import burp.Logs.LogEntryMenu;
import burp.Logs.LogManager;
import burp.Logs.LogTableModel;
import burp.Replacements.Replacement;
import burp.Replacements.ReplacementTableModel;
import burp.Replacements.Replacements;
import burp.Utils.AutoRepeaterMenu;
import burp.Utils.DiffViewerPane;
import burp.Utils.HttpComparer;
import burp.Utils.StyledDiffDocument;
import burp.Utils.Utils;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;

import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.regex.PatternSyntaxException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicLong;
import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableModel;
import javax.swing.table.TableColumn;
import javax.swing.table.TableRowSorter;
import javax.swing.text.StyledDocument;

public class AutoRepeater implements IMessageEditorController {

  // UI Component Dimensions
  public static final int TEXT_HEIGHT = new JTextField().getPreferredSize().height;
  public static final int BUTTON_HEIGHT = new JButton().getPreferredSize().height;

  public static final Dimension dialogDimension = new Dimension(520, 160);
  public static final Dimension comboBoxDimension = new Dimension(260, TEXT_HEIGHT);
  public static final Dimension textFieldDimension = new Dimension(260, TEXT_HEIGHT);
  // Wide enough for "Remove" at the default font: the old 75px clipped it to "Re...".
  public static final Dimension buttonDimension = new Dimension(96, TEXT_HEIGHT);
  public static final Dimension buttonPanelDimension = new Dimension(96, TEXT_HEIGHT*7);
  public static final Dimension tableDimension = new Dimension(200, 300);
  // The configuration tables need room, otherwise every column header is truncated.

  private IBurpExtenderCallbacks callbacks;
  private IExtensionHelpers helpers;
  private Gson gson;
  private JTabbedPane tabs;

  // Splitpane that holds top and bottom halves of the ui
  private JSplitPane mainSplitPane;

  // These hold the http request viewers at the bottom
  private JSplitPane originalRequestResponseSplitPane;
  private JSplitPane modifiedRequestResponseSplitPane;

  // this split pane holds the request list and configuration panes

  private LogTable logTable;
  private TableRowSorter<LogTableModel> logTableSorter;
  private JTextField logFilterTextField;
  private JLabel logCountLabel;
  private Timer logFilterDebounce;

  private DiffViewerPane requestComparer;
  private DiffViewerPane responseComparer;

  private DiffViewerPane requestLineComparer;
  private DiffViewerPane responseLineComparer;

  // request/response viewers
  private IMessageEditor originalRequestViewer;
  private IMessageEditor originalResponseViewer;
  private IMessageEditor modifiedRequestViewer;
  private IMessageEditor modifiedResponseViewer;

  // Panels for including request/response viewers + labels
  private JPanel originalRequestPanel;
  private JPanel modifiedRequestPanel;
  private JPanel originalResponsePanel;
  private JPanel modifiedResponsePanel;

  private JLabel originalRequestLabel;
  private JLabel modifiedRequestLabel;
  private JLabel originalResponseLabel;
  private JLabel modifiedResponseLabel;

  private volatile byte[] originalRequest;
  private volatile byte[] originalResponse;
  private volatile byte[] modifiedRequest;
  private volatile byte[] modifiedResponse;

  // Diffs are expensive, so they are computed off the event thread, only for the tab that is
  // actually visible, and only once per selected log entry. selectionGeneration is bumped on every
  // selection change so results for a row the user already left are thrown away.
  private final AtomicLong selectionGeneration = new AtomicLong();
  private final ExecutorService diffExecutor = Executors.newSingleThreadExecutor(runnable -> {
    Thread thread = new Thread(runnable, "AutoRepeater-diff");
    thread.setDaemon(true);
    return thread;
  });
  private long loadedGeneration = -1;
  private long charDiffGeneration = -1;
  private long lineDiffGeneration = -1;
  private StyledDocument requestDiffDocument;
  private StyledDocument responseDiffDocument;
  private StyledDocument requestLineDiffDocument;
  private StyledDocument responseLineDiffDocument;

  JScrollPane requestComparerScrollPane;
  JScrollPane responseComparerScollPane;

  JScrollPane requestLineComparerScrollPane;
  JScrollPane responseLineComparerScollPane;

  // List of log entries for LogTable
  private LogManager logManager;

  // The current item selected in the log table
  private IHttpRequestResponsePersisted currentOriginalRequestResponse;
  private IHttpRequestResponsePersisted currentModifiedRequestResponse;

  // The tabbed pane that holds the configuration options
  private JPanel configurationPane;
  // Activate toggle and status, shown in the log toolbar so they stay visible on every tab
  private JPanel activatedPanel;
  private JTabbedPane configurationTabbedPane;

  // The button that indicates weather AutoRepeater is active.
  private JToggleButton activatedButton;

  // Elements for configuration panel
  private Conditions conditions;
  private ConditionTableModel conditionsTableModel;

  private Replacements replacements;
  private ReplacementTableModel replacementsTableModel;

  private Replacements baseReplacements;
  private ReplacementTableModel baseReplacementsTableModel;

  private Filters filters;
  private FilterTableModel filterTableModel;

  private Highlighters highlighters;
  private HighlighterUITableModel highlighterUITableModel;

  public AutoRepeater() {
    this.callbacks = BurpExtender.getCallbacks();
    helpers = callbacks.getHelpers();
    gson = BurpExtender.getGson();
    conditions = new Conditions();
    conditionsTableModel = conditions.getConditionTableModel();
    replacements = new Replacements();
    replacementsTableModel = replacements.getReplacementTableModel();
    baseReplacements = new Replacements();
    baseReplacementsTableModel = baseReplacements.getReplacementTableModel();
    logManager = new LogManager();
    logTable = new LogTable(logManager.getLogTableModel());
    logTableSorter = new TableRowSorter<>(logManager.getLogTableModel());
    filters = new Filters(logManager);
    filterTableModel = filters.getFilterTableModel();
    highlighters = new Highlighters(logManager, logTable);
    highlighterUITableModel = highlighters.getHighlighterUITableModel();
    createUI();
    setDefaultState();
    activatedButton.setSelected(true);
  }

  public AutoRepeater(JsonObject configurationJson) {
    this();
    loadConfiguration(configurationJson);
  }

  /** Replaces the current configuration (not the log) with the one in the given json. */
  public void loadConfiguration(JsonObject configurationJson) {
    // clear out everything, including the defaults from the constructor
    conditionsTableModel.clear();
    filterTableModel.clear();
    baseReplacementsTableModel.clear();
    replacementsTableModel.clear();
    highlighterUITableModel.clear();
    // Initialize singular properties
    if (configurationJson.get("isActivated") != null) {
      activatedButton.setSelected(configurationJson.get("isActivated").getAsBoolean());
    }
    if (configurationJson.get("isWhitelistFilter") != null) {
      filters.setWhitelist(configurationJson.get("isWhitelistFilter").getAsBoolean());
    }
    // Initialize lists
    if (configurationJson.get("baseReplacements") != null) {
      for (JsonElement element : configurationJson.getAsJsonArray("baseReplacements")) {
        baseReplacementsTableModel.addReplacement(gson.fromJson(element, Replacement.class));
      }
    }
    if (configurationJson.get("replacements") != null) {
      for (JsonElement element : configurationJson.getAsJsonArray("replacements")) {
        replacementsTableModel.addReplacement(gson.fromJson(element, Replacement.class));
      }
    }
    if (configurationJson.get("conditions") != null) {
      for (JsonElement element : configurationJson.getAsJsonArray("conditions")) {
        conditionsTableModel.add(gson.fromJson(element, Condition.class));
      }
    }
    if (configurationJson.get("filters") != null) {
      for (JsonElement element : configurationJson.getAsJsonArray("filters")) {
        filterTableModel.add(gson.fromJson(element, Filter.class));
      }
    }
    if (configurationJson.get("highlighters") != null) {
      for (JsonElement element : configurationJson.getAsJsonArray("highlighters")) {
        HighlighterTableModel tempHighlighterTableModel = new HighlighterTableModel();
        JsonObject elementObject = element.getAsJsonObject();
        if (elementObject.get("color") != null) {
          tempHighlighterTableModel.setColorName(elementObject.get("color").getAsString());
        }
        if (elementObject.get("comment") != null) {
          if (!elementObject.get("comment").isJsonNull()) {
            tempHighlighterTableModel.setComment(elementObject.get("comment").getAsString());
          } else {
            tempHighlighterTableModel.setComment("");
          }
        }
        if (elementObject.get("enabled") != null) {
          tempHighlighterTableModel.setEnabled(elementObject.get("enabled").getAsBoolean());
        }
        for (JsonElement highlighter : elementObject.get("highlighters").getAsJsonArray()) {
          tempHighlighterTableModel.add(gson.fromJson(highlighter, Highlighter.class));
        }
        highlighterUITableModel.add(tempHighlighterTableModel);
      }
    }
    // If something was empty, put in the default values
    if(conditionsTableModel.getConditions().size() == 0) {
      setDefaultConditions();
    }
    if(filterTableModel.getFilters().size() == 0) {
      setDefaultFilters();
    }
    conditionsTableModel.fireTableDataChanged();
    filterTableModel.fireTableDataChanged();
  }

  public void setDefaultConditions() {
    conditionsTableModel.add(new Condition(
        "",
        "Sent From Tool",
        "Burp",
        ""
    ));

    conditionsTableModel.add(new Condition(
        "Or",
        "Request",
        "Contains Parameters",
        "",
        false
    ));

    conditionsTableModel.add(new Condition(
        "Or",
        "HTTP Method",
        "Does Not Match",
        "(GET|POST)",
        false
    ));

    conditionsTableModel.add(new Condition(
        "And",
        "URL",
        "Is In Scope",
        "",
        false
    ));
  }

  public void setDefaultFilters() {
    filterTableModel.add(new Filter(
        "",
        "Original",
        "Sent From Tool",
        "Burp",
        ""
    ));
  }

  private void setDefaultState() {
    setDefaultConditions();
    setDefaultFilters();
  }

  /** Prompts for a file and writes the current configuration to it as pretty-printed JSON. */
  private void exportConfiguration() {
    JFileChooser fileChooser = new JFileChooser();
    fileChooser.setDialogTitle("Export AutoRepeater Configuration");
    fileChooser.setSelectedFile(new File("autorepeater-config.json"));
    int result = fileChooser.showSaveDialog(getUI());
    if (result != JFileChooser.APPROVE_OPTION) {
      return;
    }
    File file = fileChooser.getSelectedFile();
    String json = new GsonBuilder().setPrettyPrinting().create().toJson(toJson());
    try {
      Files.write(file.toPath(), json.getBytes(StandardCharsets.UTF_8));
      JOptionPane.showMessageDialog(getUI(),
          "Configuration exported to " + file.getAbsolutePath(),
          "Export Config", JOptionPane.INFORMATION_MESSAGE);
    } catch (IOException e) {
      JOptionPane.showMessageDialog(getUI(),
          "Failed to write configuration: " + e.getMessage(),
          "Export Config", JOptionPane.ERROR_MESSAGE);
    }
  }

  /**
   * Prompts for a file and replaces the current configuration with the one in it. Confirms first
   * since this discards whatever replacements, conditions, filters and highlighters are set up.
   */
  private void importConfiguration() {
    JFileChooser fileChooser = new JFileChooser();
    fileChooser.setDialogTitle("Import AutoRepeater Configuration");
    int result = fileChooser.showOpenDialog(getUI());
    if (result != JFileChooser.APPROVE_OPTION) {
      return;
    }
    File file = fileChooser.getSelectedFile();
    String json;
    try {
      json = new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8);
    } catch (IOException e) {
      JOptionPane.showMessageDialog(getUI(),
          "Failed to read configuration: " + e.getMessage(),
          "Import Config", JOptionPane.ERROR_MESSAGE);
      return;
    }
    JsonObject configurationJson;
    try {
      JsonElement parsed = new JsonParser().parse(json);
      // Accept the legacy one-tab-per-element array format as well as a plain object.
      if (parsed.isJsonArray()) {
        if (parsed.getAsJsonArray().size() == 0) {
          throw new JsonSyntaxException("configuration array is empty");
        }
        configurationJson = parsed.getAsJsonArray().get(0).getAsJsonObject();
      } else {
        configurationJson = parsed.getAsJsonObject();
      }
    } catch (JsonSyntaxException | IllegalStateException e) {
      JOptionPane.showMessageDialog(getUI(),
          "Not a valid AutoRepeater configuration file: " + e.getMessage(),
          "Import Config", JOptionPane.ERROR_MESSAGE);
      return;
    }
    int confirm = JOptionPane.showConfirmDialog(getUI(),
        "This will replace the current replacements, conditions, filters and highlighters. Continue?",
        "Import Config", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
    if (confirm != JOptionPane.YES_OPTION) {
      return;
    }
    loadConfiguration(configurationJson);
  }

  public JsonObject toJson() {
    JsonObject autoRepeaterJson = new JsonObject();
    // Add Static Properties
    autoRepeaterJson.addProperty("isActivated", activatedButton.isSelected());
    autoRepeaterJson.addProperty("isWhitelistFilter", filters.isWhitelist());
    // Add Arrays
    JsonArray baseReplacementsArray = new JsonArray();
    JsonArray replacementsArray = new JsonArray();
    JsonArray conditionsArray = new JsonArray();
    JsonArray filtersArray = new JsonArray();
    JsonArray highlightersArray = new JsonArray();
    for (Condition c : conditionsTableModel.getConditions()) {
      conditionsArray.add(gson.toJsonTree(c));
    }
    for (Replacement r : baseReplacementsTableModel.getReplacements()) {
      baseReplacementsArray.add(gson.toJsonTree(r));
    }
    for (Replacement r : replacementsTableModel.getReplacements()) {
      replacementsArray.add(gson.toJsonTree(r));
    }
    for (Filter f : filterTableModel.getFilters()) {
      filtersArray.add(gson.toJsonTree(f));
    }
    for (HighlighterTableModel htm : highlighterUITableModel.getTableModels()) {
      JsonArray tempHighlightersArray = new JsonArray();
      for (Highlighter h : htm.getHighlighters()) {
        tempHighlightersArray.add(gson.toJsonTree(h));
      }
      JsonObject highlighterTableObject = new JsonObject();
      highlighterTableObject.addProperty("color", htm.getColorName());
      highlighterTableObject.addProperty("comment", htm.getComment());
      highlighterTableObject.addProperty("enabled", htm.isEnabled());
      highlighterTableObject.add("highlighters", tempHighlightersArray);
      highlightersArray.add(highlighterTableObject);
    }
    autoRepeaterJson.add("baseReplacements", baseReplacementsArray);
    autoRepeaterJson.add("replacements", replacementsArray);
    autoRepeaterJson.add("conditions", conditionsArray);
    autoRepeaterJson.add("filters", filtersArray);
    autoRepeaterJson.add("highlighters", highlightersArray);
    return autoRepeaterJson;
  }

  public JSplitPane getUI() {
    return mainSplitPane;
  }

  public LogTable getLogTable() {
    return logTable;
  }

  public LogManager getLogManager() {
    return logManager;
  }

  private void createUI() {
    GridBagConstraints c;
    Border grayline = BorderFactory.createLineBorder(Color.GRAY);
    // main splitpane
    mainSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
    // splitpane that holds request and response viewers
    originalRequestResponseSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
    modifiedRequestResponseSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
    // This tabbedpane includes the configuration panels
    configurationTabbedPane = new JTabbedPane();
    // Initialize Activated Button. No fixed size: the label was clipped to "Deactivate AutoRepe..."
    // whenever the look and feel used a larger font than the hard-coded 200px allowed for.
    activatedButton = new JToggleButton("Activate AutoRepeater");
    JLabel activatedStatusLabel = new JLabel();
    activatedButton.addChangeListener(e -> {
      boolean active = activatedButton.isSelected();
      activatedButton.setText(active ? "Deactivate AutoRepeater" : "Activate AutoRepeater");
      activatedStatusLabel.setText(active ? "Active" : "Inactive");
      activatedStatusLabel.setForeground(active
          ? Utils.getBurpOrange()
          : UIManager.getColor("Label.disabledForeground"));
    });
    activatedButton.setToolTipText(
        "When active, every message matching the conditions below is replayed with the replacements applied");
    activatedStatusLabel.setFont(Utils.getHeaderFont(activatedStatusLabel.getFont()));

    JButton exportConfigButton = new JButton("Export Config");
    exportConfigButton.setToolTipText("Save the current configuration (replacements, conditions, filters, highlighters) to a file");
    exportConfigButton.addActionListener(e -> exportConfiguration());

    JButton importConfigButton = new JButton("Import Config");
    importConfigButton.setToolTipText("Replace the current configuration with one loaded from a file");
    importConfigButton.addActionListener(e -> importConfiguration());

    activatedPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
    activatedPanel.add(activatedButton);
    activatedPanel.add(activatedStatusLabel);
    activatedPanel.add(exportConfigButton);
    activatedPanel.add(importConfigButton);

    configurationPane = new JPanel();
    configurationPane.setLayout(new BorderLayout());
    configurationPane.add(configurationTabbedPane, BorderLayout.CENTER);
    JTabbedPane replacementsTabbedPane = new JTabbedPane();
    JTabbedPane logsTabbedPane = new JTabbedPane();

    replacementsTabbedPane.addTab("Base Replacements", baseReplacements.getUI());
    replacementsTabbedPane.addTab("Replacements", replacements.getUI());
    replacementsTabbedPane.addTab("Conditions", conditions.getUI());

    logsTabbedPane.addTab("Log Filter", filters.getUI());
    logsTabbedPane.addTab("Log Highlighter", highlighters.getUI());

    configurationTabbedPane.add("Replacements", replacementsTabbedPane);
    configurationTabbedPane.add("Logs", logsTabbedPane);

    // table of log entries
    logTable.setDefaultRenderer(Object.class, new LogCellRenderer(SwingConstants.LEADING));
    // Counts and lengths read better right aligned.
    logTable.setDefaultRenderer(Integer.class, new LogCellRenderer(SwingConstants.TRAILING));
    logTable.setDefaultRenderer(Long.class, new LogCellRenderer(SwingConstants.TRAILING));

    logTable.setRowSorter(logTableSorter);
    // Newest request first: this is a live log, so the interesting row is the one that just arrived.
    logTableSorter.setSortKeys(
        Collections.singletonList(new RowSorter.SortKey(0, SortOrder.DESCENDING)));
    logTable.setShowVerticalLines(false);
    logTable.setIntercellSpacing(new Dimension(0, 1));
    logTable.setRowHeight(Math.max(logTable.getRowHeight(), TEXT_HEIGHT));
    logTable.getTableHeader().setReorderingAllowed(false);
    // Every column except the URL has a fixed upper bound, so the URL absorbs all spare width.
    logTable.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);

    // preferred widths; column 2 (URL) is unbounded
    final int[] columnWidths = {50, 70, 420, 100, 70, 100, 100, 120};
    for (int i = 0; i < columnWidths.length; i++) {
      TableColumn column = logTable.getColumnModel().getColumn(i);
      column.setPreferredWidth(columnWidths[i]);
      if (i != 2) {
        column.setMinWidth(columnWidths[i]);
        column.setMaxWidth(columnWidths[i]);
      } else {
        column.setMinWidth(150);
      }
    }

    JScrollPane logTableScrollPane = new JScrollPane(logTable);
    logTableScrollPane.setBorder(BorderFactory.createEmptyBorder());

    JPanel logPanel = new JPanel(new BorderLayout());
    logPanel.add(createLogToolbar(), BorderLayout.NORTH);
    logPanel.add(logTableScrollPane, BorderLayout.CENTER);
    logPanel.setMinimumSize(new Dimension(360, 120));
    logPanel.setPreferredSize(new Dimension(10000, 280));

    // tabs with request/response viewers
    tabs = new JTabbedPane();

    tabs.addChangeListener(e -> updateRequestViewers());

    // Request / Response Viewers
    originalRequestViewer = callbacks.createMessageEditor(this, false);
    originalResponseViewer = callbacks.createMessageEditor(this, false);
    modifiedRequestViewer = callbacks.createMessageEditor(this, false);
    modifiedResponseViewer = callbacks.createMessageEditor(this, false);

    // Request / Response Labels
    originalRequestLabel = new JLabel("Request");
    originalResponseLabel = new JLabel("Response");
    modifiedRequestLabel = new JLabel("Request");
    modifiedResponseLabel = new JLabel("Response");

    JLabel diffRequestLabel = new JLabel("Request");
    JLabel diffResponseLabel = new JLabel("Response");

    JLabel lineDiffRequestLabel = new JLabel("Request");
    JLabel lineDiffResponseLabel = new JLabel("Response");

    originalRequestLabel.setForeground(Utils.getBurpOrange());
    originalResponseLabel.setForeground(Utils.getBurpOrange());
    modifiedRequestLabel.setForeground(Utils.getBurpOrange());
    modifiedResponseLabel.setForeground(Utils.getBurpOrange());
    diffRequestLabel.setForeground(Utils.getBurpOrange());
    diffResponseLabel.setForeground(Utils.getBurpOrange());
    lineDiffRequestLabel.setForeground(Utils.getBurpOrange());
    lineDiffResponseLabel.setForeground(Utils.getBurpOrange());

    // Derived from the look and feel font so the headers follow Burp's font size setting instead of
    // being pinned to 14pt SansSerif.
    for (JLabel label : new JLabel[]{originalRequestLabel, originalResponseLabel,
        modifiedRequestLabel, modifiedResponseLabel, diffRequestLabel, diffResponseLabel,
        lineDiffRequestLabel, lineDiffResponseLabel}) {
      label.setFont(Utils.getHeaderFont(label.getFont()));
      label.setBorder(BorderFactory.createEmptyBorder(2, 4, 2, 4));
    }

    // Initialize JPanels that hold request/response viewers and labels
    originalRequestPanel = new JPanel();
    modifiedRequestPanel = new JPanel();

    originalResponsePanel = new JPanel();
    modifiedResponsePanel = new JPanel();

    originalRequestPanel.setLayout(new BoxLayout(originalRequestPanel, BoxLayout.PAGE_AXIS));
    modifiedRequestPanel.setLayout(new BoxLayout(modifiedRequestPanel, BoxLayout.PAGE_AXIS));
    originalResponsePanel.setLayout(new BoxLayout(originalResponsePanel, BoxLayout.PAGE_AXIS));
    modifiedResponsePanel.setLayout(new BoxLayout(modifiedResponsePanel, BoxLayout.PAGE_AXIS));

    // Diff viewer stuff
    JSplitPane diffSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);

    JPanel requestDiffPanel = new JPanel();
    JPanel responseDiffPanel = new JPanel();

    requestDiffPanel.setPreferredSize(new Dimension(100000, 100000));
    responseDiffPanel.setPreferredSize(new Dimension(100000, 100000));

    requestDiffPanel.setLayout(new GridBagLayout());
    responseDiffPanel.setLayout(new GridBagLayout());

    requestComparer = new DiffViewerPane();
    responseComparer = new DiffViewerPane();

    requestComparerScrollPane = new JScrollPane(requestComparer);
    responseComparerScollPane = new JScrollPane(responseComparer);

    c = new GridBagConstraints();
    c.anchor = GridBagConstraints.FIRST_LINE_START;
    requestDiffPanel.add(createDiffHeader(diffRequestLabel), c);
    c.gridy = 1;
    c.weightx = 1;
    c.weighty = 1;
    c.fill = GridBagConstraints.BOTH;
    requestDiffPanel.add(requestComparerScrollPane, c);

    c = new GridBagConstraints();
    c.anchor = GridBagConstraints.FIRST_LINE_START;
    responseDiffPanel.add(createDiffHeader(diffResponseLabel), c);
    c.gridy = 1;
    c.weightx = 1;
    c.weighty = 1;
    c.fill = GridBagConstraints.BOTH;
    responseDiffPanel.add(responseComparerScollPane, c);

    // Line Diff Viewer Stuff
    JSplitPane lineDiffSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);

    JPanel requestLineDiffPanel = new JPanel();
    JPanel responseLineDiffPanel = new JPanel();

    requestLineDiffPanel.setPreferredSize(new Dimension(100000, 100000));
    responseLineDiffPanel.setPreferredSize(new Dimension(100000, 100000));

    requestLineDiffPanel.setLayout(new GridBagLayout());
    responseLineDiffPanel.setLayout(new GridBagLayout());

    requestLineComparer = new DiffViewerPane();
    responseLineComparer = new DiffViewerPane();

    requestLineComparerScrollPane = new JScrollPane(requestLineComparer);
    responseLineComparerScollPane = new JScrollPane(responseLineComparer);

    c = new GridBagConstraints();
    c.anchor = GridBagConstraints.FIRST_LINE_START;
    requestLineDiffPanel.add(createDiffHeader(lineDiffRequestLabel), c);
    c.gridy = 1;
    c.weightx = 1;
    c.weighty = 1;
    c.fill = GridBagConstraints.BOTH;
    requestLineDiffPanel.add(requestLineComparerScrollPane, c);

    c = new GridBagConstraints();
    c.anchor = GridBagConstraints.FIRST_LINE_START;
    responseLineDiffPanel.add(createDiffHeader(lineDiffResponseLabel), c);
    c.gridy = 1;
    c.weightx = 1;
    c.weighty = 1;
    c.fill = GridBagConstraints.BOTH;
    responseLineDiffPanel.add(responseLineComparerScollPane, c);

    // Add Viewers
    originalRequestPanel.add(originalRequestLabel);
    originalRequestPanel.add(originalRequestViewer.getComponent());
    originalRequestPanel.setPreferredSize(new Dimension(100000, 100000));

    originalResponsePanel.add(originalResponseLabel);
    originalResponsePanel.add(originalResponseViewer.getComponent());
    originalResponsePanel.setPreferredSize(new Dimension(100000, 100000));

    modifiedRequestPanel.add(modifiedRequestLabel);
    modifiedRequestPanel.add(modifiedRequestViewer.getComponent());
    modifiedRequestPanel.setPreferredSize(new Dimension(100000, 100000));

    modifiedResponsePanel.add(modifiedResponseLabel);
    modifiedResponsePanel.add(modifiedResponseViewer.getComponent());
    modifiedResponsePanel.setPreferredSize(new Dimension(100000, 100000));

    // Add viewers to the original splitpane
    originalRequestResponseSplitPane.setLeftComponent(originalRequestPanel);
    originalRequestResponseSplitPane.setRightComponent(originalResponsePanel);

    originalRequestResponseSplitPane.setResizeWeight(0.50);
    tabs.addTab("Original", originalRequestResponseSplitPane);

    // Add viewers to the modified splitpane
    modifiedRequestResponseSplitPane.setLeftComponent(modifiedRequestPanel);
    modifiedRequestResponseSplitPane.setRightComponent(modifiedResponsePanel);
    modifiedRequestResponseSplitPane.setResizeWeight(0.5);
    tabs.addTab("Modified", modifiedRequestResponseSplitPane);

    // Add diff tab
    diffSplitPane.setLeftComponent(requestDiffPanel);
    diffSplitPane.setRightComponent(responseDiffPanel);
    diffSplitPane.setResizeWeight(0.50);
    tabs.addTab("Diff", diffSplitPane);

    //Add line diff tab
    lineDiffSplitPane.setLeftComponent(requestLineDiffPanel);
    lineDiffSplitPane.setRightComponent(responseLineDiffPanel);
    lineDiffSplitPane.setResizeWeight(0.50);
    tabs.addTab("Line Diff", lineDiffSplitPane);

    // Global configuration lives next to the viewers so the log table can use the full width
    tabs.addTab("Configuration", configurationPane);

    // Both halves grow with the window. The old weight of 1e-14 gave every extra pixel to the
    // request viewers and left the log table stuck at its initial height.
    mainSplitPane.setResizeWeight(0.35);
    mainSplitPane.setBottomComponent(tabs);

    mainSplitPane.setTopComponent(logPanel);

    // Keep the split panes at the bottom the same size.
    originalRequestResponseSplitPane.addPropertyChangeListener(JSplitPane.DIVIDER_LOCATION_PROPERTY,
        pce -> {
          modifiedRequestResponseSplitPane.setDividerLocation(
              originalRequestResponseSplitPane.getDividerLocation());
          diffSplitPane.setDividerLocation(
              originalRequestResponseSplitPane.getDividerLocation());
          lineDiffSplitPane.setDividerLocation(
              originalRequestResponseSplitPane.getDividerLocation());
        }
    );
    modifiedRequestResponseSplitPane.addPropertyChangeListener(JSplitPane.DIVIDER_LOCATION_PROPERTY,
        pce -> {
          originalRequestResponseSplitPane.setDividerLocation(
              modifiedRequestResponseSplitPane.getDividerLocation());
          diffSplitPane.setDividerLocation(
              modifiedRequestResponseSplitPane.getDividerLocation());
          lineDiffSplitPane.setDividerLocation(
              modifiedRequestResponseSplitPane.getDividerLocation());
        }
    );
    diffSplitPane.addPropertyChangeListener(JSplitPane.DIVIDER_LOCATION_PROPERTY,
        pce -> {
          originalRequestResponseSplitPane.setDividerLocation(
              diffSplitPane.getDividerLocation());
          modifiedRequestResponseSplitPane.setDividerLocation(
              diffSplitPane.getDividerLocation());
          lineDiffSplitPane.setDividerLocation(
              diffSplitPane.getDividerLocation());
        }
    );
    lineDiffSplitPane.addPropertyChangeListener(JSplitPane.DIVIDER_LOCATION_PROPERTY,
        pce -> {
          originalRequestResponseSplitPane.setDividerLocation(
              lineDiffSplitPane.getDividerLocation());
          modifiedRequestResponseSplitPane.setDividerLocation(
              lineDiffSplitPane.getDividerLocation());
          diffSplitPane.setDividerLocation(
              lineDiffSplitPane.getDividerLocation());
        }
    );

    // I don't know what this actually does but I think it's correct
    callbacks.customizeUiComponent(mainSplitPane);
    callbacks.customizeUiComponent(logTable);
    callbacks.customizeUiComponent(logTableScrollPane);
    callbacks.customizeUiComponent(logPanel);
    callbacks.customizeUiComponent(tabs);
  }

  public boolean isActivated() {
    return activatedButton.isSelected();
  }

  public void modifyAndSendRequestAndLog(
      int toolFlag,
      IHttpRequestResponse messageInfo ) {
    if (!activatedButton.isSelected() || toolFlag == IBurpExtenderCallbacks.TOOL_EXTENDER) {
      return;
    }
    if (!conditionsTableModel.check(toolFlag, messageInfo)) {
      return;
    }
    final byte[] baseRequest = messageInfo.getRequest();
    // Keyed by request bytes: the cloned IHttpRequestResponse objects don't implement equals(), so
    // the HashSet used here previously never actually de-duplicated anything and identical
    // replacements were sent twice.
    Map<ByteBuffer, IHttpRequestResponse> requestSet = new LinkedHashMap<>();
    IHttpRequestResponse baseReplacedRequestResponse = Utils
        .cloneIHttpRequestResponse(messageInfo);
    // Perform all the base replacements on the captured request
    for (Replacement globalReplacement : baseReplacementsTableModel.getReplacements()) {
      baseReplacedRequestResponse.setRequest(
          globalReplacement.performReplacement(baseReplacedRequestResponse));
    }
    //Add the base replaced request to the request set
    if (replacementsTableModel.getReplacements().isEmpty()) {
      requestSet.put(
          ByteBuffer.wrap(baseReplacedRequestResponse.getRequest()), baseReplacedRequestResponse);
    }
    // Perform all the separate replacements on the request+base replacements and add them to the set
    for (Replacement replacement : replacementsTableModel.getReplacements()) {
      IHttpRequestResponse newHttpRequest = Utils
          .cloneIHttpRequestResponse(baseReplacedRequestResponse);
      newHttpRequest.setRequest(replacement.performReplacement(newHttpRequest));
      requestSet.putIfAbsent(ByteBuffer.wrap(newHttpRequest.getRequest()), newHttpRequest);
    }
    // Perform every unique request and log
    for (IHttpRequestResponse request : requestSet.values()) {
      if (Arrays.equals(request.getRequest(), baseRequest)) {
        continue;
      }
      IHttpRequestResponse modifiedRequestResponse =
          callbacks.makeHttpRequest(messageInfo.getHttpService(), request.getRequest());
      if (AutoRepeaterMenu.sendRequestsToPassiveScanner) {
        callbacks.doPassiveScan(
            modifiedRequestResponse.getHttpService().getHost(),
            modifiedRequestResponse.getHttpService().getPort(),
            modifiedRequestResponse.getHttpService().getProtocol().equals("https"),
            modifiedRequestResponse.getRequest(),
            modifiedRequestResponse.getResponse()
        );
      }
      if (AutoRepeaterMenu.addRequestsToSiteMap) {
        callbacks.addToSiteMap(modifiedRequestResponse);
      }

      if (modifiedRequestResponse.getResponse() == null) {
        modifiedRequestResponse.setResponse(new byte[0]);
      }

      LogEntry newLogEntry = new LogEntry(
          logManager.nextLogId(),
          toolFlag,
          callbacks.saveBuffersToTempFiles(messageInfo),
          callbacks.saveBuffersToTempFiles(modifiedRequestResponse));
      // Highlight the row. The table repaint is left to the batched insert below.
      highlighters.applyHighlights(newLogEntry);
      logManager.addEntry(newLogEntry, filters);
    }
  }

  public LogTableModel getLogTableModel() {
    return logManager.getLogTableModel();
  }

  // Implement IMessageEditorController. Burp calls these before anything is selected, hence the
  // null checks.
  @Override
  public byte[] getRequest() {
    IHttpRequestResponsePersisted requestResponse = getCurrentRequestResponse();
    return requestResponse == null ? new byte[0] : requestResponse.getRequest();
  }

  @Override
  public byte[] getResponse() {
    IHttpRequestResponsePersisted requestResponse = getCurrentRequestResponse();
    return requestResponse == null ? new byte[0] : requestResponse.getResponse();
  }

  @Override
  public IHttpService getHttpService() {
    IHttpRequestResponsePersisted requestResponse = getCurrentRequestResponse();
    return requestResponse == null ? null : requestResponse.getHttpService();
  }

  private IHttpRequestResponsePersisted getCurrentRequestResponse() {
    switch (tabs.getSelectedIndex()) {
      case 0:
        return currentOriginalRequestResponse;
      case 1:
        return currentModifiedRequestResponse;
      default:
        return null;
    }
  }

  /**
   * Reads the request/response bodies of the selected entry off the event thread (they live in
   * Burp's temp files) and then refreshes whichever tab is visible.
   */
  private void selectLogEntry(LogEntry logEntry) {
    final long generation = selectionGeneration.incrementAndGet();
    diffExecutor.submit(() -> {
      byte[] newOriginalRequest = logEntry.getOriginalRequestResponse().getRequest();
      byte[] newOriginalResponse = logEntry.getOriginalRequestResponse().getResponse();
      byte[] newModifiedRequest = logEntry.getModifiedRequestResponse().getRequest();
      byte[] newModifiedResponse = logEntry.getModifiedRequestResponse().getResponse();
      SwingUtilities.invokeLater(() -> {
        if (generation != selectionGeneration.get()) {
          return;
        }
        originalRequest = newOriginalRequest;
        originalResponse = newOriginalResponse;
        modifiedRequest = newModifiedRequest;
        modifiedResponse = newModifiedResponse;
        currentOriginalRequestResponse = logEntry.getOriginalRequestResponse();
        currentModifiedRequestResponse = logEntry.getModifiedRequestResponse();
        loadedGeneration = generation;
        // Invalidate cached diffs; they are recomputed lazily if a diff tab is open.
        requestDiffDocument = null;
        responseDiffDocument = null;
        requestLineDiffDocument = null;
        responseLineDiffDocument = null;
        updateRequestViewers();
      });
    });
  }

  private void updateOriginalRequestResponseViewer() {
    originalRequestViewer.setMessage(originalRequest == null ? new byte[0] : originalRequest, true);
    originalResponseViewer
        .setMessage(originalResponse == null ? new byte[0] : originalResponse, false);
  }

  private void updateModifiedRequestResponseViewer() {
    modifiedRequestViewer.setMessage(modifiedRequest == null ? new byte[0] : modifiedRequest, true);
    modifiedResponseViewer
        .setMessage(modifiedResponse == null ? new byte[0] : modifiedResponse, false);
  }

  private void updateDiffViewer() {
    if (requestDiffDocument != null && responseDiffDocument != null) {
      requestComparer.setDiffDocument(requestDiffDocument);
      responseComparer.setDiffDocument(responseDiffDocument);
      return;
    }
    if (originalRequest == null || modifiedRequest == null) {
      requestComparer.clearDiff();
      responseComparer.clearDiff();
      return;
    }
    final long generation = loadedGeneration;
    if (charDiffGeneration == generation) {
      // A diff for this row is already being computed.
      return;
    }
    charDiffGeneration = generation;
    requestComparer.setDiffDocument(StyledDiffDocument.ofText("Computing diff..."));
    responseComparer.setDiffDocument(StyledDiffDocument.ofText("Computing diff..."));
    final byte[] oRequest = originalRequest;
    final byte[] mRequest = modifiedRequest;
    final byte[] oResponse = originalResponse;
    final byte[] mResponse = modifiedResponse;
    diffExecutor.submit(() -> {
      StyledDocument request = HttpComparer
          .diffTextDocument(asString(oRequest), asString(mRequest));
      StyledDocument response = HttpComparer
          .diffTextDocument(asString(oResponse), asString(mResponse));
      SwingUtilities.invokeLater(() -> {
        if (generation != selectionGeneration.get()) {
          return;
        }
        requestDiffDocument = request;
        responseDiffDocument = response;
        if (tabs.getSelectedIndex() == 2) {
          requestComparer.setDiffDocument(request);
          responseComparer.setDiffDocument(response);
        }
      });
    });
  }

  private void updateLineDiffViewer() {
    if (requestLineDiffDocument != null && responseLineDiffDocument != null) {
      requestLineComparer.setDiffDocument(requestLineDiffDocument);
      responseLineComparer.setDiffDocument(responseLineDiffDocument);
      return;
    }
    if (originalRequest == null || modifiedRequest == null) {
      requestLineComparer.clearDiff();
      responseLineComparer.clearDiff();
      return;
    }
    final long generation = loadedGeneration;
    if (lineDiffGeneration == generation) {
      return;
    }
    lineDiffGeneration = generation;
    requestLineComparer.setDiffDocument(StyledDiffDocument.ofText("Computing diff..."));
    responseLineComparer.setDiffDocument(StyledDiffDocument.ofText("Computing diff..."));
    final byte[] oRequest = originalRequest;
    final byte[] mRequest = modifiedRequest;
    final byte[] oResponse = originalResponse;
    final byte[] mResponse = modifiedResponse;
    diffExecutor.submit(() -> {
      StyledDocument request = HttpComparer
          .diffLinesDocument(asString(oRequest), asString(mRequest));
      StyledDocument response = HttpComparer
          .diffLinesDocument(asString(oResponse), asString(mResponse));
      SwingUtilities.invokeLater(() -> {
        if (generation != selectionGeneration.get()) {
          return;
        }
        requestLineDiffDocument = request;
        responseLineDiffDocument = response;
        if (tabs.getSelectedIndex() == 3) {
          requestLineComparer.setDiffDocument(request);
          responseLineComparer.setDiffDocument(response);
        }
      });
    });
  }

  private static String asString(byte[] bytes) {
    return bytes == null ? "" : new String(bytes, StandardCharsets.ISO_8859_1);
  }

  private void updateRequestViewers() {
    switch (tabs.getSelectedIndex()) {
      case 0:
        updateOriginalRequestResponseViewer();
        break;
      case 1:
        updateModifiedRequestResponseViewer();
        break;
      case 2:
        updateDiffViewer();
        break;
      case 3:
        updateLineDiffViewer();
        break;
      default:
        // Configuration tab: nothing to refresh
        break;
    }
  }

  /** Diff pane header: the title plus a legend for the two highlight colours. */
  private static JComponent createDiffHeader(JLabel titleLabel) {
    JPanel header = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 2));
    header.add(titleLabel);
    header.add(createLegendSwatch("added", DiffViewerPane.insertBackground()));
    header.add(createLegendSwatch("removed", DiffViewerPane.deleteBackground()));
    return header;
  }

  private static JLabel createLegendSwatch(String text, Color background) {
    JLabel swatch = new JLabel(text);
    swatch.setOpaque(true);
    swatch.setBackground(background);
    swatch.setForeground(Utils.getContrastingForeground(background));
    swatch.setBorder(BorderFactory.createCompoundBorder(
        BorderFactory.createLineBorder(background.darker()),
        BorderFactory.createEmptyBorder(1, 5, 1, 5)));
    return swatch;
  }

  /**
   * Search field, row count and a clear button above the log table. Clearing the log used to be
   * reachable only from the right click menu and there was no way to search the log at all.
   */
  private JComponent createLogToolbar() {
    JPanel toolbar = new JPanel(new GridBagLayout());
    toolbar.setBorder(BorderFactory.createEmptyBorder(4, 6, 4, 6));

    logFilterTextField = new JTextField();
    logFilterTextField.setToolTipText(
        "Show only rows containing this text. Prefix with \"re:\" for a regular expression.");
    logFilterTextField.putClientProperty("JTextField.placeholderText", "Search logs");
    // Debounced: re-filtering walks every row, so it should not run on every keystroke.
    logFilterDebounce = new Timer(200, e -> applyQuickFilter());
    logFilterDebounce.setRepeats(false);
    logFilterTextField.getDocument().addDocumentListener(new DocumentListener() {
      @Override
      public void insertUpdate(DocumentEvent e) {
        logFilterDebounce.restart();
      }

      @Override
      public void removeUpdate(DocumentEvent e) {
        logFilterDebounce.restart();
      }

      @Override
      public void changedUpdate(DocumentEvent e) {
        logFilterDebounce.restart();
      }
    });

    logCountLabel = new JLabel();
    logCountLabel.setForeground(UIManager.getColor("Label.disabledForeground"));

    JButton clearLogButton = new JButton("Clear");
    clearLogButton.setToolTipText("Remove every logged request from this tab");
    clearLogButton.addActionListener(e -> {
      if (logManager.getLogTableModel().getLogCount() == 0) {
        return;
      }
      int confirm = JOptionPane.showConfirmDialog(getUI(),
          "This will permanently remove every logged request from this tab. Continue?",
          "Clear Logs", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
      if (confirm != JOptionPane.YES_OPTION) {
        return;
      }
      logManager.getLogTableModel().clearLogs();
      updateLogCountLabel();
    });

    GridBagConstraints c = new GridBagConstraints();
    c.gridy = 0;
    c.insets = new Insets(0, 0, 0, 6);
    c.anchor = GridBagConstraints.LINE_START;
    toolbar.add(activatedPanel, c);
    toolbar.add(new JLabel("Search:"), c);
    c.fill = GridBagConstraints.HORIZONTAL;
    c.weightx = 1;
    toolbar.add(logFilterTextField, c);
    c.fill = GridBagConstraints.NONE;
    c.weightx = 0;
    toolbar.add(logCountLabel, c);
    c.insets = new Insets(0, 0, 0, 0);
    toolbar.add(clearLogButton, c);

    logManager.getLogTableModel().addTableModelListener(e -> updateLogCountLabel());
    updateLogCountLabel();
    return toolbar;
  }

  private void applyQuickFilter() {
    String text = logFilterTextField.getText().trim();
    if (text.isEmpty()) {
      logTableSorter.setRowFilter(null);
    } else if (text.startsWith("re:")) {
      try {
        logTableSorter.setRowFilter(RowFilter.regexFilter(text.substring(3)));
      } catch (PatternSyntaxException e) {
        // Incomplete expression while typing: keep the previous filter.
        return;
      }
    } else {
      final String needle = text.toLowerCase(Locale.ROOT);
      logTableSorter.setRowFilter(new RowFilter<LogTableModel, Integer>() {
        @Override
        public boolean include(Entry<? extends LogTableModel, ? extends Integer> entry) {
          for (int i = 0; i < entry.getValueCount(); i++) {
            Object value = entry.getValue(i);
            if (value != null && value.toString().toLowerCase(Locale.ROOT).contains(needle)) {
              return true;
            }
          }
          return false;
        }
      });
    }
    updateLogCountLabel();
  }

  private void updateLogCountLabel() {
    if (logCountLabel == null) {
      return;
    }
    int shown = logTable.getRowCount();
    int total = logManager.getLogTableModel().getLogCount();
    logCountLabel.setText(shown == total
        ? shown + (shown == 1 ? " request" : " requests")
        : shown + " of " + total + " requests");
  }

  /**
   * Paints highlighter colours with a readable foreground, and falls back to the look and feel's own
   * colours for unhighlighted rows. Previously every row was painted with a hard-coded white
   * background, which is unreadable under Burp's dark themes.
   */
  private class LogCellRenderer extends DefaultTableCellRenderer {

    LogCellRenderer(int alignment) {
      setHorizontalAlignment(alignment);
    }

    @Override
    public Component getTableCellRendererComponent(
        JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
      Component component =
          super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
      LogEntry logEntry = null;
      int modelRow = table.convertRowIndexToModel(row);
      if (modelRow >= 0 && modelRow < logManager.getRowCount()) {
        logEntry = logManager.getLogEntry(modelRow);
      }
      Color highlight = logEntry == null ? null : logEntry.getBackgroundColor();
      boolean isHighlighted = highlight != null && !highlight.equals(Highlighter.COLORS[0]);
      if (isSelected) {
        Color background =
            isHighlighted ? logEntry.getSelectedBackgroundColor() : table.getSelectionBackground();
        component.setBackground(background);
        component.setForeground(isHighlighted
            ? Utils.getContrastingForeground(background) : table.getSelectionForeground());
      } else {
        Color background = isHighlighted ? highlight : table.getBackground();
        component.setBackground(background);
        component.setForeground(isHighlighted
            ? Utils.getContrastingForeground(background) : table.getForeground());
      }
      return component;
    }
  }

  // JTable for Viewing Logs
  public class LogTable extends JTable {

    public LogTable(TableModel tableModel) {
      super(tableModel);
      // Registered once. The original code added a new listener on every selection change, so the
      // popup menu was rebuilt and shown once per past selection and the table got slower with
      // every click.
      addMouseListener(new MouseAdapter() {
        @Override
        public void mouseReleased(MouseEvent e) {
          onMouseEvent(e);
        }

        @Override
        public void mousePressed(MouseEvent e) {
          onMouseEvent(e);
        }

        private void onMouseEvent(MouseEvent e) {
          if (!e.isPopupTrigger()) {
            return;
          }
          Point p = e.getPoint();
          int viewRow = rowAtPoint(p);
          int viewColumn = columnAtPoint(p);
          if (viewRow < 0 || viewColumn < 0) {
            return;
          }
          final int row = convertRowIndexToModel(viewRow);
          final int col = convertColumnIndexToModel(viewColumn);
          getSelectionModel().setSelectionInterval(viewRow, viewRow);
          new LogEntryMenu(logManager, filters, LogTable.this, row, col)
              .show(e.getComponent(), e.getX(), e.getY());
        }
      });
    }

    /** URLs are wider than the column, so the full value is shown on hover. */
    @Override
    public String getToolTipText(MouseEvent event) {
      int viewRow = rowAtPoint(event.getPoint());
      int viewColumn = columnAtPoint(event.getPoint());
      if (viewRow < 0 || viewColumn < 0) {
        return null;
      }
      Object value = getValueAt(viewRow, viewColumn);
      return value == null ? null : value.toString();
    }

    @Override
    public void changeSelection(int row, int col, boolean toggle, boolean extend) {
      super.changeSelection(row, col, toggle, extend);
      if (row < 0 || row >= getRowCount()) {
        return;
      }
      int modelRow = convertRowIndexToModel(row);
      if (modelRow < 0 || modelRow >= logManager.getRowCount()) {
        return;
      }
      selectLogEntry(logManager.getLogEntry(modelRow));
    }
  }
}
