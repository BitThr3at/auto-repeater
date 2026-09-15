package burp.Utils;

import java.util.LinkedList;
import javax.swing.text.StyledDocument;

public class HttpComparer {

  /** Character level diffing is quadratic in the worst case, so the input is capped. */
  private static final int MAX_CHAR_DIFF_INPUT = 100_000;
  private static final int MAX_LINE_DIFF_INPUT = 300_000;

  /** Wall clock budget for a single diff, in seconds. */
  private static final float DIFF_TIMEOUT = 2.0f;

  /**
   * Character level diff. Returns a document ready to be handed to a
   * {@link DiffViewerPane} on the event thread; safe to call off the event thread.
   */
  public static StyledDocument diffTextDocument(String original, String modified) {
    if (original.length() > MAX_CHAR_DIFF_INPUT || modified.length() > MAX_CHAR_DIFF_INPUT) {
      return StyledDiffDocument.ofText(
          "Input too large for a character diff (limit " + MAX_CHAR_DIFF_INPUT
              + " characters). Use the Line Diff tab.");
    }
    diff_match_patch differ = new diff_match_patch();
    differ.Diff_Timeout = DIFF_TIMEOUT;
    LinkedList<diff_match_patch.Diff> diff = differ.diff_main(original, modified, true);
    differ.diff_cleanupSemantic(diff);
    return StyledDiffDocument.ofDiff(diff);
  }

  /**
   * Line level diff. Returns a document ready to be handed to a
   * {@link DiffViewerPane} on the event thread; safe to call off the event thread.
   */
  public static StyledDocument diffLinesDocument(String original, String modified) {
    if (original.length() > MAX_LINE_DIFF_INPUT || modified.length() > MAX_LINE_DIFF_INPUT) {
      return StyledDiffDocument.ofText(
          "Input too large for a line diff (limit " + MAX_LINE_DIFF_INPUT + " characters).");
    }
    diff_match_patch differ = new diff_match_patch();
    differ.Diff_Timeout = DIFF_TIMEOUT;
    diff_match_patch.LinesToCharsResult linesToChars = differ
        .diff_linesToChars(original, modified);
    LinkedList<diff_match_patch.Diff> diff = differ
        .diff_main(linesToChars.chars1, linesToChars.chars2, false);
    differ.diff_charsToLines(diff, linesToChars.lineArray);
    return StyledDiffDocument.ofDiff(diff);
  }
}
