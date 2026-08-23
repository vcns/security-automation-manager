/**
 * Comment deduplication and body construction. Pure functions -- given an
 * already-fetched comment list, decide what to do; given findings, build
 * the body text. I/O (pagination, posting) lives in github.mjs / main.mjs.
 *
 * Every model-produced string (`evidence`, `remediation`) and every
 * attacker-influenceable string derived from the diff (file paths) is
 * sanitised via sanitize.mjs before being interpolated into the comment
 * body -- treated as untrusted output, not merely validated input.
 * validate-findings.mjs having already confirmed a finding's `file`/`line`
 * correspond to something genuinely in the diff does not mean the
 * `evidence`/`remediation` text, or the file path's own characters, are
 * safe to interpolate into Markdown unescaped.
 */
import { sanitizeModelText, sanitizeFilePath } from './sanitize.mjs';

export const MARKER = '<!-- openai-review:v1 -->';
export const MAX_PUBLISHED_FINDINGS = 20;
const SEVERITY_ORDER = { blocking: 0, advisory: 1, nit: 2 };
const SEVERITY_LABEL = { blocking: 'Blocking', advisory: 'Advisory', nit: 'Nit' };

/**
 * Finds this pipeline's own marked comment among a PR's comments, if any.
 * A marker string appearing in a comment NOT authored by the expected bot
 * identity is never treated as this pipeline's comment -- a contributor
 * could otherwise post a comment containing the marker text to hijack
 * deduplication (e.g. to have their own comment silently edited, or to
 * prevent a real review from ever being posted as a new comment).
 *
 * @param {object[]} comments - full, already-paginated comment list
 * @param {string} expectedAuthorLogin - e.g. "github-actions[bot]"
 * @returns {object | null}
 */
export function findExistingMarkedComment(comments, expectedAuthorLogin) {
  return (
    comments.find(
      (comment) =>
        typeof comment.body === 'string' &&
        comment.body.includes(MARKER) &&
        comment.user?.login === expectedAuthorLogin &&
        comment.user?.type === 'Bot'
    ) ?? null
  );
}

/**
 * @param {Array<{file: string, line: number, severity: string, evidence: string, remediation: string}>} findings
 * @param {Array<{filename: string, reason: string}>} excludedFiles
 * @returns {string}
 */
export function buildReviewCommentBody(findings, excludedFiles) {
  const sorted = [...findings].sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 3) - (SEVERITY_ORDER[b.severity] ?? 3));
  const shown = sorted.slice(0, MAX_PUBLISHED_FINDINGS);
  const omittedCount = sorted.length - shown.length;

  const lines = [
    '## AI-assisted code review',
    '',
    '**These findings are AI-generated and unverified. They require human review and judgement before acting on any of them -- do not treat a finding, or its absence, as authoritative.**',
    '',
  ];

  if (shown.length === 0) {
    lines.push('No findings for this revision.');
  } else {
    for (const finding of shown) {
      const safeFile = sanitizeFilePath(finding.file);
      const location = finding.side === 'old' ? `former line ${finding.line}` : `line ${finding.line}`;
      lines.push(`### ${SEVERITY_LABEL[finding.severity] ?? finding.severity}: \`${safeFile}\` (${location})`);
      lines.push('');
      lines.push(sanitizeModelText(finding.evidence));
      lines.push('');
      lines.push(`**Suggested fix:** ${sanitizeModelText(finding.remediation)}`);
      lines.push('');
    }
  }

  if (omittedCount > 0) {
    lines.push(`_${omittedCount} further finding(s) were produced but not published (capped at ${MAX_PUBLISHED_FINDINGS} per review)._`);
    lines.push('');
  }

  if (excludedFiles.length > 0) {
    lines.push('<details><summary>Files not reviewed</summary>', '');
    for (const { filename, reason } of excludedFiles) {
      lines.push(`- \`${sanitizeFilePath(filename)}\`: ${reason}`);
    }
    lines.push('', '</details>', '');
  }

  lines.push(MARKER);
  return lines.join('\n');
}

/**
 * @param {string} reason - plain-language reason, no account/token detail
 * @returns {string}
 */
export function buildUnavailableCommentBody(reason) {
  return [
    '## AI-assisted code review',
    '',
    `_Automated review was not completed for this revision: ${reason}. This is advisory tooling only and does not block merging._`,
    '',
    MARKER,
  ].join('\n');
}
