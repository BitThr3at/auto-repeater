package burp.Utils;

import java.awt.Color;
import java.util.List;
import javax.swing.text.BadLocationException;
import javax.swing.text.DefaultStyledDocument;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;

/**
 * Builds the document shown by {@link DiffViewerPane}.
 *
 * Documents are built while detached from any component, so this can run on a background thread;
 * only the final setDocument() call has to happen on the event thread.
 */
public class StyledDiffDocument {

  /** Documents larger than this are truncated: rendering is linear in document size. */
  private static final int MAX_RENDERED_CHARS = 250_000;

  private static final SimpleAttributeSet EQUAL_STYLE = new SimpleAttributeSet();

  /** Built per document so a theme switch is picked up. */
  private static SimpleAttributeSet style(Color background) {
    SimpleAttributeSet attributes = new SimpleAttributeSet();
    StyleConstants.setBackground(attributes, background);
    StyleConstants.setForeground(attributes, DiffViewerPane.foreground());
    return attributes;
  }

  private StyledDiffDocument() {
  }

  public static StyledDocument ofText(String text) {
    DefaultStyledDocument document = new DefaultStyledDocument();
    try {
      document.insertString(0, text, EQUAL_STYLE);
    } catch (BadLocationException e) {
      // Inserting at 0 into an empty document cannot fail.
    }
    return document;
  }

  /**
   * The whole diff is inserted in a single mutation and the inserted/deleted runs are then
   * restyled, which is far cheaper than one insert per segment.
   */
  public static StyledDocument ofDiff(List<diff_match_patch.Diff> diffs) {
    StringBuilder text = new StringBuilder();
    // start/length/isInsert triples for the runs that need colouring
    int[] starts = new int[diffs.size()];
    int[] lengths = new int[diffs.size()];
    boolean[] isInsert = new boolean[diffs.size()];
    int runCount = 0;
    boolean truncated = false;

    for (diff_match_patch.Diff diff : diffs) {
      String segment = diff.text;
      if (text.length() + segment.length() > MAX_RENDERED_CHARS) {
        segment = segment.substring(0, Math.max(0, MAX_RENDERED_CHARS - text.length()));
        truncated = true;
      }
      if (diff.operation != diff_match_patch.Operation.EQUAL && !segment.isEmpty()) {
        starts[runCount] = text.length();
        lengths[runCount] = segment.length();
        isInsert[runCount] = diff.operation == diff_match_patch.Operation.INSERT;
        runCount++;
      }
      text.append(segment);
      if (truncated) {
        break;
      }
    }
    if (truncated) {
      text.append("\n\n[diff truncated: output exceeds ")
          .append(MAX_RENDERED_CHARS)
          .append(" characters]");
    }

    SimpleAttributeSet insertStyle = style(DiffViewerPane.insertBackground());
    SimpleAttributeSet deleteStyle = style(DiffViewerPane.deleteBackground());
    DefaultStyledDocument document = new DefaultStyledDocument();
    try {
      document.insertString(0, text.toString(), EQUAL_STYLE);
      for (int i = 0; i < runCount; i++) {
        document.setCharacterAttributes(
            starts[i], lengths[i], isInsert[i] ? insertStyle : deleteStyle, false);
      }
    } catch (BadLocationException e) {
      return ofText("Unable to render diff.");
    }
    return document;
  }
}
