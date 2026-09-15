package burp.Utils;

import java.awt.Color;
import java.awt.Font;
import javax.swing.JTextPane;
import javax.swing.UIManager;
import javax.swing.text.StyledDocument;

/**
 * Displays a diff as styled text.
 *
 * The previous implementation was a JEditorPane rendering "text/html" and the diff was handed to it
 * as one <span> element per diff segment. Parsing and laying out that document happened on the
 * Swing event thread and took seconds for anything but tiny responses, which is what froze the UI.
 * Styled text has no parsing step and the document can be built off the event thread by
 * {@link StyledDiffDocument}.
 */
public class DiffViewerPane extends JTextPane {

  private static final Color LIGHT_INSERT_BACKGROUND = new Color(0xd6f5d6);
  private static final Color LIGHT_DELETE_BACKGROUND = new Color(0xffd6d6);
  private static final Color DARK_INSERT_BACKGROUND = new Color(0x1f4620);
  private static final Color DARK_DELETE_BACKGROUND = new Color(0x5c1f22);

  public DiffViewerPane() {
    setEditable(false);
    // Plain text: response bodies are never interpreted as markup any more.
    setContentType("text/plain");
    putClientProperty("html.disable", Boolean.TRUE);
    setFont(new Font(Font.MONOSPACED, Font.PLAIN, getFont().getSize()));
  }

  /** The pastel palette is unreadable on Burp's dark themes, so the colours follow the theme. */
  public static Color insertBackground() {
    return Utils.isDarkTheme() ? DARK_INSERT_BACKGROUND : LIGHT_INSERT_BACKGROUND;
  }

  public static Color deleteBackground() {
    return Utils.isDarkTheme() ? DARK_DELETE_BACKGROUND : LIGHT_DELETE_BACKGROUND;
  }

  public static Color foreground() {
    Color foreground = UIManager.getColor("TextPane.foreground");
    return foreground == null ? (Utils.isDarkTheme() ? Color.WHITE : Color.BLACK) : foreground;
  }

  /**
   * Swaps in a document built off the event thread. Must be called on the event thread.
   */
  public void setDiffDocument(StyledDocument document) {
    setDocument(document);
    setCaretPosition(0);
  }

  public void clearDiff() {
    setDiffDocument(StyledDiffDocument.ofText(""));
  }
}
