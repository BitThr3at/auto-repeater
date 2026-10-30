package burp;

/**
 * Created by j on 8/7/17.
 */

import burp.Utils.AutoRepeaterMenu;
import burp.Utils.Utils;
import com.google.gson.*;

import java.awt.*;
import java.awt.event.*;
import java.util.*;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import javax.swing.*;
import javax.swing.Timer;

public class BurpExtender implements IBurpExtender, ITab, IHttpListener, IContextMenuFactory {

  // burp stuff
  private static IBurpExtenderCallbacks callbacks;
  private static IExtensionHelpers helpers;
  private static Gson gson;

  private static JTabbedPane parentTabbedPane;
  private static AutoRepeaterMenu autoRepeaterMenu;
  private ExecutorService executor;

  // The single, global AutoRepeater.
  private static AutoRepeater autoRepeater;

  @Override
  public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
    // keep a reference to our callbacks object
    BurpExtender.callbacks = callbacks;
    // obtain an extension helpers object
    BurpExtender.helpers = callbacks.getHelpers();
    // Gson for serialization
    BurpExtender.gson = new Gson();
    //BurpExtender.gson = new GsonBuilder().setPrettyPrinting().create();
    // Bounded queue with CallerRuns: under heavy proxy traffic an unbounded queue just grows until
    // the extension runs out of memory. Blocking the submitting thread throttles instead.
    ThreadPoolExecutor threadPoolExecutor = new ThreadPoolExecutor(
        4, 25, 60L, TimeUnit.SECONDS, new ArrayBlockingQueue<>(500),
        runnable -> {
          Thread thread = new Thread(runnable, "AutoRepeater-worker");
          thread.setDaemon(true);
          return thread;
        },
        new ThreadPoolExecutor.CallerRunsPolicy());
    threadPoolExecutor.allowCoreThreadTimeOut(true);
    executor = threadPoolExecutor;
    // create our UI
    SwingUtilities.invokeLater(() -> {
      // If there is a saved extensionSetting load it.
      String b64ConfigurationJson = callbacks.loadExtensionSetting(getTabCaption());
      if (b64ConfigurationJson != null) {
        initializeFromSave(b64ConfigurationJson);
      }
      if (autoRepeater == null) {
        setAutoRepeater(new AutoRepeater());
      }

      // Set Extension Name
      callbacks.setExtensionName("AutoRepeater");
      // register As An HTTP Listener
      callbacks.registerHttpListener(BurpExtender.this);
      // Add To Right Click Menu
      callbacks.registerContextMenuFactory(BurpExtender.this);
      // Add response store
      //Save State
      callbacks.registerExtensionStateListener(
          () -> {
            callbacks.saveExtensionSetting(getTabCaption(), exportSave());
            executor.shutdownNow();
          }
      );
      // Add A Custom Tab To Burp
      callbacks.addSuiteTab(BurpExtender.this);
      // set parent component
      parentTabbedPane = (JTabbedPane) getUiComponent().getParent();

      if (parentTabbedPane != null) {
        autoRepeaterMenu = new AutoRepeaterMenu(parentTabbedPane.getRootPane());
        SwingUtilities.invokeLater(autoRepeaterMenu);
      } else {
        getUiComponent().addHierarchyListener(new MenuCreatingHierarchyListener());
      }
    });
  }

  private class MenuCreatingHierarchyListener implements HierarchyListener {
    @Override
    public void hierarchyChanged(HierarchyEvent e) {
      if (getUiComponent().getParent() != null) {
        // set parent component
        parentTabbedPane = (JTabbedPane) getUiComponent().getParent();
        autoRepeaterMenu = new AutoRepeaterMenu(parentTabbedPane.getRootPane());
        autoRepeaterMenu.run();
        getUiComponent().removeHierarchyListener(this);
      }
    }
  }

  public static AutoRepeaterMenu getAutoRepeaterMenu() {
    return autoRepeaterMenu;
  }

  public static JTabbedPane getParentTabbedPane() {
    return parentTabbedPane;
  }

  public static String exportSave() {
    return autoRepeater.toJson().toString();
  }

  /**
   * Loads a saved configuration. Older saves are an array with one object per tab; only the
   * first is used now that the configuration is global.
   */
  public static void initializeFromSave(String configuration) {
    getCallbacks().printOutput("Loading Stored AutoRepeater Configuration");
    String configurationJson;
    // Check if the configuration is B64 encoded for legacy.
    try {
      configurationJson = new String(Base64.getDecoder().decode(configuration));
    } catch (IllegalArgumentException e) {
      configurationJson = configuration;
    }
    JsonElement parsed = new JsonParser().parse(configurationJson);
    JsonObject tabConfiguration = null;
    if (parsed.isJsonArray()) {
      if (parsed.getAsJsonArray().size() > 0) {
        tabConfiguration = parsed.getAsJsonArray().get(0).getAsJsonObject();
      }
    } else if (parsed.isJsonObject()) {
      tabConfiguration = parsed.getAsJsonObject();
    }
    if (tabConfiguration == null) {
      return;
    }
    if (autoRepeater == null) {
      setAutoRepeater(new AutoRepeater(tabConfiguration));
    } else {
      // Keep the instance: its UI is the tab Burp already shows.
      autoRepeater.loadConfiguration(tabConfiguration);
    }
  }

  private static void setAutoRepeater(AutoRepeater newAutoRepeater) {
    autoRepeater = newAutoRepeater;
  }

  public static void highlightTab() {
    if (parentTabbedPane != null) {
      for (int i = 0; i < parentTabbedPane.getTabCount(); i++) {
        if (parentTabbedPane.getComponentAt(i).equals(autoRepeater.getUI())) {
          parentTabbedPane.setBackgroundAt(i, Utils.getBurpOrange());
          Timer timer = new Timer(3000, e -> {
            for (int j = 0; j < parentTabbedPane.getTabCount(); j++) {
              if (parentTabbedPane.getComponentAt(j).equals(autoRepeater.getUI())) {
                parentTabbedPane.setBackgroundAt(j, Color.BLACK);
                break;
              }
            }
          });
          timer.setRepeats(false);
          timer.start();
          break;
        }
      }
    }
  }

  // implement ITab
  @Override
  public String getTabCaption() {
    return "AutoRepeater";
  }

  @Override
  public Component getUiComponent() {
    return autoRepeater.getUI();
  }

  // implement IHttpListener
  @Override
  public void processHttpMessage(
      int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
    if (messageIsRequest || toolFlag == IBurpExtenderCallbacks.TOOL_EXTENDER) {
      return;
    }
    // Checked here as well so a deactivated extension costs nothing on Burp's HTTP threads.
    if (!autoRepeater.isActivated()) {
      return;
    }
    executor.submit(
        () -> autoRepeater.modifyAndSendRequestAndLog(
            toolFlag,
            messageInfo)
    );
  }

  public static AutoRepeater getAutoRepeater() {
    return autoRepeater;
  }

  public static IBurpExtenderCallbacks getCallbacks() {
    return callbacks;
  }

  public static IExtensionHelpers getHelpers() {
    return helpers;
  }

  public static Gson getGson() {
    return gson;
  }

  @Override
  public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
    ArrayList<JMenuItem> menu = new ArrayList<>();
    ActionListener listener;
    final int toolFlag = invocation.getToolFlag();
    IHttpRequestResponse[] requestResponses = invocation.getSelectedMessages();

    listener = event -> new Thread(() -> {
      if (toolFlag != -1) {
        BurpExtender.highlightTab();
        for (IHttpRequestResponse requestResponse : requestResponses) {
          final IHttpRequestResponse tempRequestResponse;
          if (requestResponse.getResponse() == null) {
            tempRequestResponse = BurpExtender.getCallbacks().makeHttpRequest(
                requestResponse.getHttpService(), requestResponse.getRequest());
          } else {
            tempRequestResponse = requestResponse;
          }
          executor.submit(() -> autoRepeater.modifyAndSendRequestAndLog(
              toolFlag,
              tempRequestResponse));
        }
      }
    }).start();

    JMenuItem item = new JMenuItem("Send to AutoRepeater", null);
    item.addActionListener(listener);
    menu.add(item);
    return menu;
  }
}
