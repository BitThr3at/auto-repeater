package burp.Conditions;

import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IParameter;
import burp.IRequestInfo;
import burp.IResponseInfo;
import com.google.common.io.Files;

import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class Condition {

  private String booleanOperator;
  private String matchType;
  private String matchRelationship;
  private String matchCondition;
  private boolean isEnabled;

  /**
   * Conditions are evaluated for every message Burp sees, and String.matches()/Pattern.compile()
   * re-parse the pattern on every call. The compiled pattern is cached instead. transient keeps it
   * out of the Gson serialisation of saved configurations.
   */
  private transient volatile CompiledPattern patternCache;

  private static final class CompiledPattern {
    final String source;
    final Pattern pattern;

    CompiledPattern(String source, Pattern pattern) {
      this.source = source;
      this.pattern = pattern;
    }
  }

  private Pattern matchPattern() {
    String source = this.matchCondition;
    CompiledPattern cached = patternCache;
    if (cached != null && cached.source.equals(source)) {
      return cached.pattern;
    }
    Pattern pattern;
    try {
      pattern = Pattern.compile(source);
    } catch (RuntimeException e) {
      // Invalid regex: treat it as matching nothing rather than throwing on every message.
      pattern = null;
    }
    patternCache = new CompiledPattern(source, pattern);
    return pattern;
  }

  /** Equivalent of String.matches(matchCondition), with the pattern cached. */
  private boolean matchesFully(String input) {
    Pattern pattern = matchPattern();
    return pattern != null && pattern.matcher(input).matches();
  }

  /** Equivalent of Pattern.compile(matchCondition).matcher(input).find(), with the pattern cached. */
  private boolean matchesAnywhere(String input) {
    Pattern pattern = matchPattern();
    return pattern != null && pattern.matcher(input).find();
  }

  public Condition(
      String booleanOperator,
      String matchType,
      String matchRelationship,
      String matchCondition) {
    setEnabled(true);
    setBooleanOperator(booleanOperator);
    setMatchType(matchType);
    setMatchRelationship(matchRelationship);
    setMatchCondition(matchCondition);
  }

  public Condition(
      String booleanOperator,
      String matchType,
      String matchRelationship,
      String matchCondition,
      boolean isEnabled) {
    setEnabled(isEnabled);
    setBooleanOperator(booleanOperator);
    setMatchType(matchType);
    setMatchRelationship(matchRelationship);
    setMatchCondition(matchCondition);
  }

  public static final String[] BOOLEAN_OPERATOR_OPTIONS = {
      "And",
      "Or"
  };

  public static final String[] MATCH_TYPE_OPTIONS = {
      "String In Request",
      "String In Response",
      "Request Length",
      "Response Length",
      "URL",
      "Status Code",
      "Domain Name",
      //"IP Address",
      "Protocol",
      "HTTP Method",
      "File Extension",
      "Request",
      "Cookie Name",
      "Cookie Value",
      "Any Header",
      "Request Body",
      "Param Name",
      "Param Value",
      "Sent From Tool",
      "Listener Port"
  };

  public boolean checkCondition(int toolFlag, IHttpRequestResponse messageInfo) {
    switch (this.matchType) {
      case "Domain Name": return checkDomainName(messageInfo);
      case "Protocol": return checkProtocol(messageInfo);
      case "HTTP Method": return checkHttpMethod(messageInfo);
      case "URL": return checkUrl(messageInfo);
      case "File Extension": return checkFileExtension(messageInfo);
      case "Request": return checkRequest(messageInfo);
      case "Cookie Name": return checkCookieName(messageInfo);
      case "Cookie Value": return checkCookieValue(messageInfo);
      case "Any Header": return checkAnyHeader(messageInfo);
      case "Request Body": return checkRequestBody(messageInfo);
      case "Param Name": return checkParamName(messageInfo);
      case "Param Value": return checkParamValue(messageInfo);
      case "Sent From Tool": return checkSentFromTool(toolFlag);
      case "Listener Port": return checkListenerPort(messageInfo);
      case "Status Code": return checkStatusCode(messageInfo);
      case "String In Request": return checkStringInRequest(messageInfo);
      case "String In Response": return checkStringInResponse(messageInfo);
      default: throw new IllegalStateException("checkCondition() not defined for the input.");
    }
  }


  public static String[] getMatchRelationshipOptions(String inputString) {
    switch (inputString) {
      case "Domain Name":
        return new String[]{"Matches", "Does Not Match"};
      case "IP Address":
        return new String[]{"Is In Range", "Is Not In Range"};
      case "Protocol":
        return new String[]{"Is HTTP", "Is Not HTTP"};
      case "HTTP Method":
        return new String[]{"Matches", "Does Not Match"};
      case "URL":
        return new String[]{"Matches", "Does Not Match", "Is In Scope", "Is Not In Scope"};
      case "File Extension":
        return new String[]{"Matches", "Does Not Match"};
      case "Request":
        return new String[]{"Contains Parameters", "Does Not Contain Parameters"};
      case "Status Code":
        return new String[]{"Is Greater Than", "Is Less Than", "Equals", "Does Not Equal"};
      case "Cookie Name":
        return new String[]{"Matches", "Does Not Match"};
      case "Cookie Value":
        return new String[]{"Matches", "Does Not Match"};
      case "Any Header":
        return new String[]{"Matches", "Does Not Match"};
      case "Request Body":
        return new String[]{"Matches", "Does Not Match"};
      case "Param Name":
        return new String[]{"Matches", "Does Not Match"};
      case "Param Value":
        return new String[]{"Matches", "Does Not Match"};
      case "Sent From Tool":
        return new String[]{
            "Burp",
            "Proxy",
            "Repeater",
            "Spider",
            "Intruder",
            "Scanner"
        };
      case "Listener Port":
        return new String[]{"Matches", "Does Not Match"};
      case "String In Request":
        return new String[]{"Matches", "Does Not Match", "Matches Regex", "Does Not Match Regex"};
      case "String In Response":
        return new String[]{"Matches", "Does Not Match", "Matches Regex", "Does Not Match Regex"};
      case "Request Length":
        return new String[]{"Is Greater Than", "Is Less Than", "Equals"};
      case "Response Length":
        return new String[]{"Is Greater Than", "Is Less Than", "Equals"};
      case "Mime Type":
        return new String[]{"Is Text", "Is Not Text", "Is Media", "Is Not Media"};
      default:
        throw new IllegalStateException("getMatchRelationshipOptions() not defined for "+inputString);
    }
  }

  public static boolean matchConditionIsEditable(String inputString) {
    switch (inputString) {
      case "Domain Name":
        return true;
      case "IP Address":
        return true;
      case "Protocol":
        return false;
      case "HTTP Method":
        return true;
      case "URL":
        return true;
      case "File Extension":
        return true;
      case "Request":
        return false;
      case "Cookie Name":
        return true;
      case "Cookie Value":
        return true;
      case "Any Header":
        return true;
      case "Request Body":
        return true;
      case "Param Name":
        return true;
      case "Param Value":
        return true;
      case "Sent From Tool":
        return false;
      case "Listener Port":
        return true;
      case "Status Code":
        return true;
      case "String In Request":
        return true;
      case "String In Response":
        return true;
      case "Request Length":
        return true;
      case "Response Length":
        return true;
      default:
        throw new IllegalStateException("matchConditionIsEditable() not defined for input "+inputString);
    }
  }

  /**
   * Whether the match condition text is compiled as a regex for the given match type/relationship.
   * A bad regex is already handled gracefully at match time (it just matches nothing, see
   * {@link #matchPattern()}), but the UI should still reject it up front rather than silently
   * creating a condition/filter that never does anything.
   */
  public static boolean matchConditionIsRegex(String matchType, String matchRelationship) {
    switch (matchType) {
      case "HTTP Method":
      case "URL":
      case "File Extension":
      case "Cookie Name":
      case "Cookie Value":
      case "Any Header":
      case "Request Body":
      case "Param Name":
      case "Param Value":
        return true;
      case "String In Request":
      case "String In Response":
        return "Matches Regex".equals(matchRelationship)
            || "Does Not Match Regex".equals(matchRelationship);
      default:
        return false;
    }
  }

  private boolean checkRequestLength(IHttpRequestResponse messageInfo) {
    try {
      int matchInt = Integer.parseInt(this.matchCondition);
      switch (this.matchRelationship) {
        case "Is Greater Than":
          return messageInfo.getRequest().length > matchInt;
        case "Is Less Than":
          return messageInfo.getRequest().length < matchInt;
        default:
          return messageInfo.getRequest().length == matchInt;
      }
    } catch(Exception NumberFormatException) {
      return false;
    }
  }

  private boolean checkResponseLength(IHttpRequestResponse messageInfo) {
    try {
      int matchInt = Integer.parseInt(this.matchCondition);
      switch (this.matchRelationship) {
        case "Is Greater Than":
          return messageInfo.getResponse().length > matchInt;
        case "Is Less Than":
          return messageInfo.getResponse().length < matchInt;
        default:
          return messageInfo.getResponse().length == matchInt;
      }
    } catch(Exception NumberFormatException) {
      return false;
    }
  }

  private boolean checkStringInRequest(IHttpRequestResponse messageInfo) {
    switch (this.matchRelationship) {
      case "Matches":
        return new String(messageInfo.getRequest()).contains(this.matchCondition);
      case "Does Not Match":
        return !(new String(messageInfo.getRequest()).contains(this.matchCondition));
      case "Matches Regex":
        return matchesAnywhere(new String(messageInfo.getRequest()));
      default:
        return !matchesAnywhere(new String(messageInfo.getRequest()));
    }
  }

  private boolean checkStringInResponse(IHttpRequestResponse messageInfo) {
    switch (this.matchRelationship) {
      case "Matches":
        return new String(messageInfo.getResponse()).contains(this.matchCondition);
      case "Does Not Match":
        return !(new String(messageInfo.getResponse()).contains(this.matchCondition));
      case "Matches Regex":
        return matchesAnywhere(new String(messageInfo.getResponse()));
      default:
        return !matchesAnywhere(new String(messageInfo.getResponse()));
    }
  }

  private boolean checkStatusCode(IHttpRequestResponse messageInfo) {
    IResponseInfo analyzedResponse = BurpExtender.getHelpers().analyzeResponse(messageInfo.getResponse());
    try {
      short responseCodeAsShort = Short.parseShort(this.matchCondition);
      switch (this.matchRelationship) {
        case "Is Greater Than":
          return analyzedResponse.getStatusCode() > responseCodeAsShort;
        case "Is Less Than":
          return analyzedResponse.getStatusCode() < responseCodeAsShort;
        case "Equals":
          return (analyzedResponse.getStatusCode() == responseCodeAsShort);
        default:
          return !(analyzedResponse.getStatusCode() == responseCodeAsShort);
      }
    } catch (NumberFormatException e) {
      return false;
    }
  }

  private boolean checkDomainName(IHttpRequestResponse messageInfo) {
    switch (this.matchRelationship) {
      case "Matches":
        return messageInfo.getHttpService().getHost().equals(this.matchCondition);
      default:
        return !messageInfo.getHttpService().getHost().equals(this.matchCondition);
    }
  }

  private boolean checkProtocol(IHttpRequestResponse messageInfo) {
    String protocol = messageInfo.getHttpService().getProtocol();
    switch (this.matchRelationship) {
      case "Is HTTP":
        return protocol.equals("http");
      default:
        return !protocol.equals("http");
    }
  }

  private boolean checkHttpMethod(IHttpRequestResponse messageInfo) {
    IRequestInfo analyzedRequest = BurpExtender.getHelpers().analyzeRequest(messageInfo);
    switch (this.matchRelationship) {
      case "Matches":
        return matchesFully(analyzedRequest.getMethod());
      default:
        return !matchesFully(analyzedRequest.getMethod());
    }
  }

  private boolean checkUrl(IHttpRequestResponse messageInfo) {
    IRequestInfo analyzedRequest = BurpExtender.getHelpers().analyzeRequest(messageInfo);
    switch (this.matchRelationship) {
      case "Is In Scope":
        return BurpExtender.getCallbacks().isInScope(analyzedRequest.getUrl());
      case "Is Not In Scope":
        return !BurpExtender.getCallbacks().isInScope(analyzedRequest.getUrl());
      case "Matches":
        return matchesFully(analyzedRequest.getUrl().toString());
      default:
        return !matchesFully(analyzedRequest.getUrl().toString());
    }
  }

  private boolean checkFileExtension(IHttpRequestResponse messageInfo) {
    IRequestInfo analyzedRequest = BurpExtender.getHelpers().analyzeRequest(messageInfo);
    // getUrl().toString() includes the query string, which can contain dots after the real
    // extension (e.g. "OPS-002.json?ref=OPS-002") and corrupts the detected extension. The path
    // alone does not.
    String fileExtension = Files.getFileExtension(analyzedRequest.getUrl().getPath());
    switch (this.matchRelationship) {
      case "Matches":
        return matchesFully(fileExtension);
      default:
        return !matchesFully(fileExtension);
    }
  }

  private boolean checkRequest(IHttpRequestResponse messageInfo) {
    IRequestInfo analyzedRequest = BurpExtender.getHelpers().analyzeRequest(messageInfo);
    long parameterCount = analyzedRequest.getParameters()
        .stream()
        .filter(
            p -> p.getType() == IParameter.PARAM_URL || p.getType() == IParameter.PARAM_BODY)
        .count();
    switch (this.matchRelationship) {
      case "Contains Parameters":
        return parameterCount > 0;
      default:
        return !(parameterCount > 0);
    }
  }

  private boolean checkCookieName(IHttpRequestResponse messageInfo) {
    IRequestInfo analyzedRequest = BurpExtender.getHelpers().analyzeRequest(messageInfo);
    boolean hasMatch = analyzedRequest.getParameters()
        .stream()
        .filter(p -> p.getType() == IParameter.PARAM_COOKIE)
        .anyMatch(p -> matchesFully(p.getName()));
    return "Matches".equals(this.matchRelationship) == hasMatch;
  }

  private boolean checkCookieValue(IHttpRequestResponse messageInfo) {
    IRequestInfo analyzedRequest = BurpExtender.getHelpers().analyzeRequest(messageInfo);
    boolean hasMatch = analyzedRequest.getParameters()
        .stream()
        .filter(p -> p.getType() == IParameter.PARAM_COOKIE)
        .anyMatch(p -> matchesFully(p.getValue()));
    return "Matches".equals(this.matchRelationship) == hasMatch;
  }

  private boolean checkAnyHeader(IHttpRequestResponse messageInfo) {
    IRequestInfo analyzedRequest = BurpExtender.getHelpers().analyzeRequest(messageInfo);
    boolean hasMatch = analyzedRequest.getHeaders()
        .stream()
        .anyMatch(this::matchesFully);
    return "Matches".equals(this.matchRelationship) == hasMatch;
  }

  private boolean checkRequestBody(IHttpRequestResponse messageInfo) {
    IRequestInfo analyzedRequest = BurpExtender.getHelpers().analyzeRequest(messageInfo);
    byte[] request = messageInfo.getRequest();
    String bodyString = new String(
        Arrays.copyOfRange(request, analyzedRequest.getBodyOffset(), request.length));
    return "Matches".equals(this.matchRelationship) == matchesFully(bodyString);
  }

  private boolean checkParamName(IHttpRequestResponse messageInfo) {
    IRequestInfo analyzedRequest = BurpExtender.getHelpers().analyzeRequest(messageInfo);
    boolean hasMatch = analyzedRequest.getParameters()
        .stream()
        .anyMatch(p -> matchesFully(p.getName()));
    return "Matches".equals(this.matchRelationship) == hasMatch;
  }

  private boolean checkParamValue(IHttpRequestResponse messageInfo) {
    IRequestInfo analyzedRequest = BurpExtender.getHelpers().analyzeRequest(messageInfo);
    boolean hasMatch = analyzedRequest.getParameters()
        .stream()
        .anyMatch(p -> matchesFully(p.getValue()));
    return "Matches".equals(this.matchRelationship) == hasMatch;
  }

  private boolean checkSentFromTool(int toolFlag) {
    switch (this.matchRelationship) {
      case "Burp":
        return toolFlag != BurpExtender.getCallbacks().TOOL_EXTENDER &&
            toolFlag != BurpExtender.getCallbacks().TOOL_SCANNER;
      case "Proxy":
        return toolFlag == BurpExtender.getCallbacks().TOOL_PROXY;
      case "Repeater":
        return toolFlag == BurpExtender.getCallbacks().TOOL_REPEATER;
      case "Spider":
        return toolFlag == BurpExtender.getCallbacks().TOOL_SPIDER;
      case "Intruder":
        return toolFlag == BurpExtender.getCallbacks().TOOL_INTRUDER;
      default:
        return toolFlag == BurpExtender.getCallbacks().TOOL_SCANNER;
    }
  }

  private boolean checkListenerPort(IHttpRequestResponse messageInfo) {
    if (this.matchType.equals("Matches")) {
      return messageInfo.getHttpService().getPort() == Integer.parseInt(this.matchCondition);
    } else {
      return !(messageInfo.getHttpService().getPort() == Integer.parseInt(this.matchCondition));
    }
  }

  public String getBooleanOperator() {
    return booleanOperator;
  }

  public void setBooleanOperator(String booleanOperator) {
    if(Arrays.stream(BOOLEAN_OPERATOR_OPTIONS).anyMatch(s -> s.equals(booleanOperator))) {
      this.booleanOperator = booleanOperator;
    } else if (booleanOperator.equals("")) {
      this.booleanOperator = booleanOperator;
    } else {
      this.booleanOperator = BOOLEAN_OPERATOR_OPTIONS[0];
    }
  }

  public String getMatchType() {
    return matchType;
  }

  public void setMatchType(String matchType) {
    if(Arrays.stream(MATCH_TYPE_OPTIONS).anyMatch(s -> s.equals(matchType))) {
      this.matchType = matchType;
    } else {
      this.matchType = MATCH_TYPE_OPTIONS[0];
    }
  }

  public String getMatchRelationship() {
    return matchRelationship;
  }

  public void setMatchRelationship(String matchRelationship) {
    this.matchRelationship = matchRelationship;
  }

  public String getMatchCondition() {
    return matchCondition;
  }

  public void setMatchCondition(String matchCondition) {
    this.matchCondition = matchCondition;
  }

  public boolean isEnabled() {
    return isEnabled;
  }

  public void setEnabled(boolean enabled) {
    isEnabled = enabled;
  }

}
