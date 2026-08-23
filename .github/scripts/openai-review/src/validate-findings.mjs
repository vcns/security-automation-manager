/**
 * Deterministic post-parse validation of model-reported findings.
 *
 * Strict Responses API schema enforcement (see review.mjs) guarantees
 * `findings` is shaped correctly (right field names, right JSON types) --
 * it does not, and cannot, guarantee the *content* of those fields is
 * truthful. A finding is still free to cite a file that was never sent, a
 * line that doesn't exist in that file's diff, or an implausibly long
 * string. This module is the deterministic check that catches that: run
 * after parsing, before anything is ever published.
 *
 * Invalid findings are rejected individually -- one bad finding does not
 * discard the whole batch -- and the caller is told how many were
 * discarded, so that count can be surfaced rather than silently dropped.
 */

const VALID_SEVERITIES = new Set(['blocking', 'advisory', 'nit']);
const MAX_EVIDENCE_LENGTH = 2000;
const MAX_REMEDIATION_LENGTH = 1000;

/**
 * Parses a unified diff patch and returns the set of new-file line numbers
 * that a review comment could legitimately target: added lines and
 * context lines (both exist in the new version of the file). Deleted-only
 * lines are excluded -- they don't exist in the new file at all, so a
 * finding citing one cannot be a genuine reference to reviewable content.
 *
 * @param {string} patch
 * @returns {Set<number>}
 */
export function extractValidLineNumbers(patch) {
  const valid = new Set();
  let newLine = null;

  for (const line of patch.split('\n')) {
    const hunkMatch = line.match(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
    if (hunkMatch) {
      newLine = Number(hunkMatch[1]);
      continue;
    }
    if (newLine === null) continue; // content before any hunk header is not addressable

    if (line.startsWith('+')) {
      valid.add(newLine);
      newLine += 1;
    } else if (line.startsWith('-')) {
      // Old-file-only line -- does not exist in, and does not advance,
      // the new-file line count.
    } else {
      // Context line (present in both old and new versions).
      valid.add(newLine);
      newLine += 1;
    }
  }

  return valid;
}

/**
 * @param {unknown} finding
 * @param {Map<string, Set<number>>} validLinesByFile
 * @returns {boolean}
 */
function isValidFinding(finding, validLinesByFile) {
  if (!finding || typeof finding !== 'object') return false;
  if (typeof finding.file !== 'string' || !validLinesByFile.has(finding.file)) return false;
  if (!VALID_SEVERITIES.has(finding.severity)) return false;
  if (typeof finding.evidence !== 'string' || finding.evidence.length === 0 || finding.evidence.length > MAX_EVIDENCE_LENGTH) return false;
  if (typeof finding.remediation !== 'string' || finding.remediation.length === 0 || finding.remediation.length > MAX_REMEDIATION_LENGTH) return false;
  if (!Number.isInteger(finding.line)) return false;

  const validLines = validLinesByFile.get(finding.file);
  return validLines.has(finding.line);
}

/**
 * @param {Array<object>} findings - as returned by review.mjs's requestReview()
 * @param {Array<{filename: string, patch: string}>} filesToSend - exactly what was sent to the model
 * @returns {{accepted: Array<object>, rejectedCount: number}}
 */
export function validateFindings(findings, filesToSend) {
  const validLinesByFile = new Map(filesToSend.map((file) => [file.filename, extractValidLineNumbers(file.patch)]));

  const accepted = [];
  let rejectedCount = 0;

  for (const finding of Array.isArray(findings) ? findings : []) {
    if (isValidFinding(finding, validLinesByFile)) {
      accepted.push(finding);
    } else {
      rejectedCount += 1;
    }
  }

  return { accepted, rejectedCount };
}
