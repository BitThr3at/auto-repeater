package burp.Utils;

import burp.BurpExtender;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IParameter;
import burp.IRequestInfo;
import burp.Logs.LogEntry;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ConcurrentHashMap;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import javax.swing.*;
import java.awt.*;
import java.util.List;

public class Utils {

  public static String exportLogEntriesToJson (ArrayList<LogEntry> logEntries, boolean exportHttp) {
    JsonArray json = new JsonArray();
    if(exportHttp) {
      for (LogEntry log : logEntries) {
        JsonObject logJson = new JsonObject();
        logJson.addProperty("#",log.getRequestResponseId());
        logJson.addProperty("Method",log.getModifiedMethod());
        logJson.addProperty("URL",log.getModifiedURL().toString());
        logJson.addProperty("Orig. Status",log.getOriginalResponseStatus());
        logJson.addProperty("Status",log.getModifiedResponseStatus());
        logJson.addProperty("Orig. Resp. Len.",log.getOriginalLength());
        logJson.addProperty("Resp. Len.",log.getModifiedLength());
        logJson.addProperty("Resp. Len. Diff.",log.getLengthDifference());
        logJson.addProperty("Orig. Request",new String(log.getOriginalRequestResponse().getRequest()));
        logJson.addProperty("Orig. Response",new String(log.getOriginalRequestResponse().getResponse()));
        logJson.addProperty("Request",new String(log.getModifiedRequestResponse().getRequest()));
        logJson.addProperty("Response",new String(log.getModifiedRequestResponse().getResponse()));
        json.add(logJson);

      }
    } else {
      for (LogEntry log : logEntries) {
        JsonObject logJson = new JsonObject();
        logJson.addProperty("#",log.getRequestResponseId());
        logJson.addProperty("Method",log.getModifiedMethod());
        logJson.addProperty("URL",log.getModifiedURL().toString());
        logJson.addProperty("Orig. Status",log.getOriginalResponseStatus());
        logJson.addProperty("Status",log.getModifiedResponseStatus());
        logJson.addProperty("Orig. Resp. Len.",log.getOriginalLength());
        logJson.addProperty("Resp. Len.",log.getModifiedLength());
        logJson.addProperty("Resp. Len. Diff.",log.getLengthDifference());
        json.add(logJson);
      }
    }
    return json.toString();
  }

  public static String readFile(File file) {
    BufferedReader br;
    StringBuilder output = new StringBuilder();
    try {
      br = new BufferedReader(new FileReader(file));
      String st;
      while ((st = br.readLine()) != null) {
        output.append(st);
      }
    } catch (IOException e) {
      return "";
    }
    return output.toString();
  }

  public static String exportLogEntriesToCsv (ArrayList<LogEntry> logEntries, boolean exportHttp) {
    StringBuilder csv = new StringBuilder();
    if(exportHttp) {
      String csvHeader =
          "#"+","+
          "Method"+","+
          "URL"+","+
          "Orig. Status"+","+
          "Status"+","+
          "Orig. Resp. Len."+","+
          "Resp. Len."+","+
          "Resp. Len. Diff."+","+
          "Orig. Request"+","+
          "Orig. Response"+","+
          "Request"+","+
          "Response"+"\n";
      csv.append(csvHeader);
      for (LogEntry log : logEntries) {
        csv.append(log.getRequestResponseId());
        csv.append(",");
        csv.append(Utils.sanitizeForCsv(log.getModifiedMethod()));
        csv.append(",");
        csv.append(Utils.sanitizeForCsv(log.getModifiedURL().toString()));
        csv.append(",");
        csv.append(log.getOriginalResponseStatus());
        csv.append(",");
        csv.append(log.getModifiedResponseStatus());
        csv.append(",");
        csv.append(log.getOriginalLength());
        csv.append(",");
        csv.append(log.getModifiedLength());
        csv.append(",");
        csv.append(log.getLengthDifference());
        csv.append(",");
        csv.append(Utils.sanitizeForCsv(new String(log.getOriginalRequestResponse().getRequest())));
        csv.append(",");
        csv.append(Utils.sanitizeForCsv(new String(log.getOriginalRequestResponse().getResponse())));
        csv.append(",");
        csv.append(Utils.sanitizeForCsv(new String(log.getModifiedRequestResponse().getRequest())));
        csv.append(",");
        csv.append(Utils.sanitizeForCsv(new String(log.getModifiedRequestResponse().getResponse())));
        csv.append("\n");
      }
    } else {
      String csvHeader = "#"+","+
          "Method"+","+
          "URL"+","+
          "Orig. Status"+","+
          "Status"+","+
          "Orig. Resp. Len."+","+
          "Resp. Len."+","+
          "Resp. Len. Diff."+"\n";
      csv.append(csvHeader);
      for (LogEntry log : logEntries) {
        csv.append(log.getRequestResponseId());
        csv.append(",");
        csv.append(Utils.sanitizeForCsv(log.getModifiedMethod()));
        csv.append(",");
        csv.append(Utils.sanitizeForCsv(log.getModifiedURL().toString()));
        csv.append(",");
        csv.append(log.getOriginalResponseStatus());
        csv.append(",");
        csv.append(log.getModifiedResponseStatus());
        csv.append(",");
        csv.append(log.getOriginalLength());
        csv.append(",");
        csv.append(log.getModifiedLength());
        csv.append(",");
        csv.append(log.getLengthDifference());
        csv.append("\n");
      }
    }
    return csv.toString();
  }

  /**
   * Quotes a CSV field per RFC 4180. The previous version called
   * replaceAll("\n", "\\n").replaceAll(",", "\\,"), where the replacement strings are parsed as
   * regex escapes: newlines were replaced with a bare "n" and commas were left untouched, so any
   * field containing a comma shifted every following column.
   */
  private static String sanitizeForCsv(String input) {
    if (input == null) {
      return "\"\"";
    }
    return "\"" + input.replace("\"", "\"\"") + "\"";
  }

  public static IHttpRequestResponse cloneIHttpRequestResponse(
      IHttpRequestResponse originalRequestResponse) {
    return new IHttpRequestResponse() {
      byte[] request = originalRequestResponse.getRequest();
      byte[] response = originalRequestResponse.getResponse();
      String comment = originalRequestResponse.getComment();
      String highlight = originalRequestResponse.getHighlight();
      IHttpService httpService = originalRequestResponse.getHttpService();

      @Override
      public byte[] getRequest() {
        return request;
      }

      @Override
      public void setRequest(byte[] message) {
        this.request = message;
      }

      @Override
      public byte[] getResponse() {
        return response;
      }

      @Override
      public void setResponse(byte[] message) {
        this.response = message;
      }

      @Override
      public String getComment() {
        return comment;
      }

      @Override
      public void setComment(String comment) {
        this.comment = comment;
      }

      @Override
      public String getHighlight() {
        return highlight;
      }

      @Override
      public void setHighlight(String color) {
        this.highlight = color;
      }

      @Override
      public IHttpService getHttpService() {
        return httpService;
      }

      @Override
      public void setHttpService(IHttpService httpService) {
        this.httpService = httpService;
      }
    };
  }

  public static String getStringAfterSubstring (String input, String substring) {
    return(input.substring(input.lastIndexOf(substring) + substring.length()));
  }

  /**
   * Compiled replacement patterns, cached because a replacement is applied to every message that
   * meets the conditions and Pattern.compile() is not cheap.
   */
  private static final ConcurrentHashMap<String, Pattern> PATTERN_CACHE = new ConcurrentHashMap<>();

  private static Pattern cachedPattern(String regex) {
    Pattern pattern = PATTERN_CACHE.get(regex);
    if (pattern == null) {
      pattern = Pattern.compile(regex);
      if (PATTERN_CACHE.size() < 256) {
        PATTERN_CACHE.put(regex, pattern);
      }
    }
    return pattern;
  }

  public static byte[] byteArrayRegexReplaceFirst(byte[] input, String regex, String replacement) {
    return byteArrayRegexReplace(input, regex, replacement, true);
  }

  public static byte[] byteArrayRegexReplaceAll(byte[] input, String regex, String replacement) {
    return byteArrayRegexReplace(input, regex, replacement, false);
  }

  /**
   * ISO-8859-1 is used because it round-trips every byte to exactly one char, so match offsets are
   * byte offsets. (US-ASCII was used before, which turns every byte above 0x7F into '?' and
   * corrupts binary request bodies.)
   *
   * The output is assembled in a ByteArrayOutputStream; the previous implementation built an
   * ArrayList&lt;Byte&gt;, boxing one object per byte of every request it touched.
   */
  private static byte[] byteArrayRegexReplace(
      byte[] input, String regex, String replacement, boolean firstOnly) {
    String inputString = new String(input, StandardCharsets.ISO_8859_1);
    Matcher matcher;
    try {
      matcher = cachedPattern(regex).matcher(inputString);
    } catch (PatternSyntaxException e) {
      return input;
    }
    if (!matcher.find()) {
      return input;
    }
    byte[] replacementBytes = replacement.getBytes(StandardCharsets.ISO_8859_1);
    ByteArrayOutputStream output = new ByteArrayOutputStream(input.length + replacementBytes.length);
    int currentIndex = 0;
    do {
      output.write(input, currentIndex, matcher.start() - currentIndex);
      output.write(replacementBytes, 0, replacementBytes.length);
      currentIndex = matcher.end();
      if (firstOnly) {
        break;
      }
    } while (matcher.find());
    output.write(input, currentIndex, input.length - currentIndex);
    return output.toByteArray();
  }

  public static byte[] byteArrayListToByteArray(ArrayList<Byte> input) {
    byte[] output = new byte[input.size()];
    for (int i = 0; i < input.size(); i++) {
      output[i] = input.get(i);
    }
    return output;
  }

  //This method isn't efficient, i should refactor
  public static String getMultipartBoundary(byte[] request) {
    IExtensionHelpers helpers = BurpExtender.getHelpers();
    IRequestInfo analyzedRequest = helpers.analyzeRequest(request);
    List<String> headers = analyzedRequest.getHeaders();
    return headers.stream()
        .filter((h) -> h.startsWith("Content-Type: multipart/form-data;"))
        .findFirst()
        .map((h) -> getStringAfterSubstring(h, "Content-Type: multipart/form-data;"))
        .map((h) -> getStringAfterSubstring(h, "boundary="))
        .map((h) -> "--"+h)
        .orElse(null);
  }

  public static Color getBurpOrange() {
    return new Color(0xff6633);
  }

  /** True when Burp is running one of the dark themes. */
  public static boolean isDarkTheme() {
    Color background = UIManager.getColor("Table.background");
    if (background == null) {
      background = UIManager.getColor("Panel.background");
    }
    return background != null && luminance(background) < 0.5;
  }

  /** Perceived brightness, 0 (black) to 1 (white). */
  public static double luminance(Color color) {
    return (0.299 * color.getRed() + 0.587 * color.getGreen() + 0.114 * color.getBlue()) / 255.0;
  }

  /**
   * Readable text colour for the given background. The highlighter palette is a set of pale
   * pastels, so on a dark theme the inherited light foreground was almost invisible on top of it.
   */
  public static Color getContrastingForeground(Color background) {
    return luminance(background) < 0.5 ? Color.WHITE : Color.BLACK;
  }

  /**
   * Shared setup for the small configuration tables. They previously had a fixed preferred size set
   * on the JTable itself, which a JScrollPane ignores for layout but does use for the viewport, so
   * columns ended up truncated ("Match Re...", "Match Co..."), and the last column now takes the
   * leftover width instead of every column shrinking equally.
   */
  public static void configureConfigurationTable(JTable table, int... preferredWidths) {
    table.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
    table.setFillsViewportHeight(true);
    table.setShowVerticalLines(false);
    table.getTableHeader().setReorderingAllowed(false);
    table.setRowHeight(Math.max(table.getRowHeight(), new JTextField().getPreferredSize().height));
    for (int column = 0; column < preferredWidths.length
        && column < table.getColumnModel().getColumnCount(); column++) {
      table.getColumnModel().getColumn(column).setPreferredWidth(preferredWidths[column]);
    }
  }

  /** Bold, one point larger than the current look and feel font, so it scales with Burp's font. */
  public static Font getHeaderFont(Font baseFont) {
    return baseFont.deriveFont(Font.BOLD, baseFont.getSize2D() + 1f);
  }

  // This method is a mess.
  public static ArrayList<IParameter> getMultipartParameters(byte[] request)  {
    IExtensionHelpers helpers = BurpExtender.getHelpers();
    IRequestInfo analyzedRequest = helpers.analyzeRequest(request);
    ArrayList<IParameter> parameters = new ArrayList<>();
    String boundary = getMultipartBoundary(request);
    String requestBodyString = new String(Arrays.copyOfRange(request, analyzedRequest.getBodyOffset(), request.length));
    int index = requestBodyString.indexOf(boundary);
    while (index >= 0) {
      //BurpExtender.getCallbacks().printOutput(Integer.toString(index));
      int nextNewLineIndex = requestBodyString.indexOf('\n', index);
      index = requestBodyString.indexOf(boundary, index+1);
    }
    return parameters;
  }

  // It seems that IParameter types are incorrectly stated by the Burp Suite API
  // so I need to check
  public static boolean isRequestMultipartForm(byte[] request) {
    IExtensionHelpers helpers = BurpExtender.getHelpers();
    IRequestInfo analyzedRequest = helpers.analyzeRequest(request);
    List<String> headers = analyzedRequest.getHeaders();
    return headers.stream().anyMatch((h) -> h.startsWith("Content-Type: multipart/form-data;"));
  }

  /**
   * Flashes the tab holding childComponent. The original colour is restored afterwards; this used to
   * hard-code black, which left the tab unreadable on light themes.
   */
  public static void highlightParentTab(JTabbedPane parentTabbedPane, Component childComponent) {
    if (parentTabbedPane == null) {
      return;
    }
    for (int i = 0; i < parentTabbedPane.getTabCount(); i++) {
      if (parentTabbedPane.getComponentAt(i).equals(childComponent)) {
        final Color previousBackground = parentTabbedPane.getBackgroundAt(i);
        parentTabbedPane.setBackgroundAt(i, getBurpOrange());
        Timer timer = new Timer(3000, e -> {
          for (int j = 0; j < parentTabbedPane.getTabCount(); j++) {
            if (parentTabbedPane.getComponentAt(j).equals(childComponent)) {
              parentTabbedPane.setBackgroundAt(j, previousBackground);
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
