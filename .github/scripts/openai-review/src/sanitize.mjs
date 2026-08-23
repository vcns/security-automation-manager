/**
 * Every string that ends up in the published comment and did not
 * originate from this script's own fixed text -- model-produced
 * `evidence`/`remediation`, file paths, excluded-file reasons -- is
 * treated as untrusted output here, not just untrusted input. Structural
 * schema enforcement (review.mjs) and content validation
 * (validate-findings.mjs) constrain what a finding can claim; this module
 * constrains what publishing it can actually *do* inside a GitHub
 * Markdown comment.
 *
 * Threats addressed specifically: user/team mentions that would notify
 * someone; raw HTML (including a hidden HTML comment that could smuggle
 * content past a casual read, or interfere with this pipeline's own
 * dedup marker); Markdown images/links that would embed or link to an
 * attacker-influenced or model-hallucinated URL; unbounded length.
 */

const MAX_TEXT_LENGTH = 4000;

/**
 * Neutralises an `@mention` so it renders as visible text without
 * notifying anyone -- a zero-width space immediately after `@` breaks
 * GitHub's mention parsing while remaining visually indistinguishable in
 * a rendered comment.
 * @param {string} text
 * @returns {string}
 */
function neutralizeMentions(text) {
  return text.replace(/@/g, '@​');
}

/**
 * Escapes HTML-significant characters so no raw HTML -- tags, hidden
 * comments, entities -- can render at all. Markdown code spans
 * (backticks) are unaffected, since `<`/`>` inside a code span are
 * escaped the same way and still render literally inside it.
 * @param {string} text
 * @returns {string}
 */
function escapeHtml(text) {
  return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

/**
 * Breaks Markdown link and image syntax (`[text](url)` / `![alt](url)`)
 * by escaping every `[` -- GitHub's Markdown renderer requires an
 * unescaped `[...]  (...)` pair to render as a clickable link or an
 * embedded image, so this alone is enough to neutralise both without
 * otherwise mangling the surrounding text.
 * @param {string} text
 * @returns {string}
 */
function neutralizeLinksAndImages(text) {
  return text.replace(/\[/g, '\\[');
}

/**
 * Full sanitisation pass for free-form model-produced prose (an
 * `evidence` or `remediation` string): length-bounded, HTML-escaped,
 * link/image syntax broken, mentions neutralised.
 * @param {string} text
 * @returns {string}
 */
export function sanitizeModelText(text) {
  const bounded = text.length > MAX_TEXT_LENGTH ? `${text.slice(0, MAX_TEXT_LENGTH)}…` : text;
  return neutralizeMentions(neutralizeLinksAndImages(escapeHtml(bounded)));
}

/**
 * Sanitises a file path for safe display inside a Markdown inline code
 * span (`` `path` ``). A path containing a backtick could otherwise break
 * out of that span; a path containing `@` could otherwise be interpreted
 * as a mention once outside the span's literal-text protection in some
 * renderers -- both are neutralised the same way as free-form text, minus
 * the length bound (paths are already bounded by filesystem limits).
 * @param {string} path
 * @returns {string}
 */
export function sanitizeFilePath(path) {
  return neutralizeMentions(path.replace(/`/g, 'ˋ')); // ` (grave accent) -> ˋ (modifier letter grave accent), visually similar, not a Markdown delimiter
}
