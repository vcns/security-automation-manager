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
const VALID_SIDES = new Set(['old', 'new']);
const MAX_EVIDENCE_LENGTH = 2000;
const MAX_REMEDIATION_LENGTH = 1000;

/**
 * Parses a unified diff patch and returns the sets of line numbers a
 * finding could legitimately cite, split by which version of the file
 * they belong to:
 *
 * - `newLines`: added and context lines -- both exist in the new version
 *   of the file, numbered as they appear there. This is what a finding
 *   about ordinary added/unchanged content should cite (`side: "new"`).
 * - `oldLines`: deleted lines -- exist only in the old version of the
 *   file (including every line of a fully deleted file, which has no
 *   `newLines` entries at all), numbered as they appeared there. This is
 *   what a finding about a removal should cite (`side: "old"`). Context
 *   lines are deliberately NOT added here even though they also exist in
 *   the old file -- citing unchanged content is unambiguous via the new
 *   side for every file except a pure deletion, so there is no case that
 *   needs a context line to be old-side-valid.
 *
 * A `\ No newline at end of file` marker is not a content line: it is
 * skipped entirely, contributing to neither set and advancing neither
 * line counter.
 *
 * @param {string} patch
 * @returns {{newLines: Set<number>, oldLines: Set<number>}}
 */
export function extractValidLineNumbers(patch) {
  const newLines = new Set();
  const oldLines = new Set();
  let newLine = null;
  let oldLine = null;

  for (const line of patch.split('\n')) {
    const hunkMatch = line.match(/^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
    if (hunkMatch) {
      oldLine = Number(hunkMatch[1]);
      newLine = Number(hunkMatch[2]);
      continue;
    }
    if (newLine === null || oldLine === null) continue; // content before any hunk header is not addressable

    if (line.startsWith('\\')) continue; // "\ No newline at end of file" -- not a content line

    if (line.startsWith('+')) {
      newLines.add(newLine);
      newLine += 1;
    } else if (line.startsWith('-')) {
      oldLines.add(oldLine);
      oldLine += 1;
    } else {
      // Context line: present in, and numbered independently in, both versions.
      newLines.add(newLine);
      newLine += 1;
      oldLine += 1;
    }
  }

  return { newLines, oldLines };
}

/**
 * @param {unknown} finding
 * @param {Map<string, {newLines: Set<number>, oldLines: Set<number>}>} diffInfoByFile
 * @returns {boolean}
 */
function isValidFinding(finding, diffInfoByFile) {
  if (!finding || typeof finding !== 'object') return false;
  if (typeof finding.file !== 'string' || !diffInfoByFile.has(finding.file)) return false;
  if (!VALID_SEVERITIES.has(finding.severity)) return false;
  if (!VALID_SIDES.has(finding.side)) return false;
  if (typeof finding.evidence !== 'string' || finding.evidence.length === 0 || finding.evidence.length > MAX_EVIDENCE_LENGTH) return false;
  if (typeof finding.remediation !== 'string' || finding.remediation.length === 0 || finding.remediation.length > MAX_REMEDIATION_LENGTH) return false;
  if (!Number.isInteger(finding.line)) return false;

  const diffInfo = diffInfoByFile.get(finding.file);
  const validLines = finding.side === 'old' ? diffInfo.oldLines : diffInfo.newLines;
  return validLines.has(finding.line);
}

/**
 * @param {Array<object>} findings - as returned by review.mjs's requestReview()
 * @param {Array<{filename: string, patch: string}>} filesToSend - exactly what was sent to the model
 * @returns {{accepted: Array<object>, rejectedCount: number}}
 */
export function validateFindings(findings, filesToSend) {
  const diffInfoByFile = new Map(filesToSend.map((file) => [file.filename, extractValidLineNumbers(file.patch)]));

  const accepted = [];
  let rejectedCount = 0;

  for (const finding of Array.isArray(findings) ? findings : []) {
    if (isValidFinding(finding, diffInfoByFile)) {
      accepted.push(finding);
    } else {
      rejectedCount += 1;
    }
  }

  return { accepted, rejectedCount };
}
