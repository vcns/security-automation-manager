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
 * attacker-influenced or model-hallucinated URL; GitHub's *bare* URL and
 * email/mailto autolinking (distinct from explicit `[text](url)` syntax);
 * line-leading Markdown block structure (headings, list items, thematic
 * breaks, fenced code blocks) that would otherwise let model text alter
 * the comment's visual structure; control characters in file paths that
 * could otherwise break the surrounding Markdown; unbounded length.
 */

const MAX_TEXT_LENGTH = 4000;

/**
 * Neutralises an `@mention` so it renders as visible text without
 * notifying anyone -- a zero-width space immediately after `@` breaks
 * GitHub's mention parsing while remaining visually indistinguishable in
 * a rendered comment. This also breaks GFM's bare-email autolinking
 * (e.g. `someone@example.com`), which is triggered by the same `@`.
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
 * escaped the same way and still render literally inside it. This also
 * removes every literal `>` character, which incidentally neutralises a
 * line-leading blockquote marker before neutralizeLeadingBlockSyntax ever
 * runs -- there is no literal `>` left for it to act on.
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
 * Breaks GitHub's *bare* URL autolinking (the GFM "extended autolinks"
 * behaviour, distinct from explicit `[text](url)` syntax, which
 * neutralizeLinksAndImages already handles) by inserting a zero-width
 * space inside the literal scheme text, so the exact scheme GitHub's
 * autolinker looks for is no longer contiguous. Covers the two schemes
 * GFM recognises as bare autolinks: `http(s)://` and `mailto:`.
 * @param {string} text
 * @returns {string}
 */
function neutralizeAutolinks(text) {
  return text
    .replace(/\bhttps?:\/\//gi, (match) => `${match.slice(0, 4)}​${match.slice(4)}`)
    .replace(/\bmailto:/gi, (match) => `${match.slice(0, 4)}​${match.slice(4)}`);
}

/**
 * Backslash-escapes the leading character of any line that would
 * otherwise be interpreted as Markdown block structure: a fenced code
 * block (three or more backticks/tildes), an ATX heading (`#`), a
 * thematic break (`---`/`***`/`___`), a bullet list item, or an ordered
 * list item. Backslash-escaping the first character of a block-starting
 * sequence is CommonMark's own documented way to force it to render as
 * literal text, so this does not depend on any particular renderer's
 * quirks -- and renders identically to the unescaped text, since a
 * CommonMark backslash escape is invisible in the rendered output.
 *
 * A leading blockquote marker (`>`) is deliberately not handled here --
 * see escapeHtml, which runs first in sanitizeModelText and already
 * removes every literal `>` character.
 * @param {string} text
 * @returns {string}
 */
function neutralizeLeadingBlockSyntax(text) {
  return text
    .split('\n')
    .map((line) => {
      const leadingWhitespace = line.match(/^[ \t]{0,3}/)[0];
      const rest = line.slice(leadingWhitespace.length);

      if (/^(`{3,}|~{3,})/.test(rest)) return leadingWhitespace + '\\' + rest;
      if (/^#{1,6}(\s|$)/.test(rest)) return leadingWhitespace + '\\' + rest;
      if (/^([-*_])(?: *\1){2,} *$/.test(rest)) return leadingWhitespace + '\\' + rest;
      if (/^[-*+](\s|$)/.test(rest)) return leadingWhitespace + '\\' + rest;
      if (/^\d{1,9}[.)](\s|$)/.test(rest)) return leadingWhitespace + rest.replace(/^(\d{1,9})([.)])/, '$1\\$2');
      return line;
    })
    .join('\n');
}

/**
 * Full sanitisation pass for free-form model-produced prose (an
 * `evidence` or `remediation` string): length-bounded, HTML-escaped,
 * line-leading block structure escaped, link/image syntax broken, bare
 * autolinks broken, mentions neutralised.
 * @param {string} text
 * @returns {string}
 */
export function sanitizeModelText(text) {
  const bounded = text.length > MAX_TEXT_LENGTH ? `${text.slice(0, MAX_TEXT_LENGTH)}…` : text;
  const htmlEscaped = escapeHtml(bounded);
  const blockEscaped = neutralizeLeadingBlockSyntax(htmlEscaped);
  const linksBroken = neutralizeLinksAndImages(blockEscaped);
  const autolinksBroken = neutralizeAutolinks(linksBroken);
  return neutralizeMentions(autolinksBroken);
}

/**
 * Sanitises a file path for safe display inside a Markdown inline code
 * span (`` `path` ``). A path containing a backtick could otherwise break
 * out of that span; a path containing `@` could otherwise be interpreted
 * as a mention once outside the span's literal-text protection in some
 * renderers -- both are neutralised the same way as free-form text, minus
 * the length bound (paths are already bounded by filesystem limits).
 * Control characters -- including a carriage return or line feed, which
 * could otherwise inject a line break and let the rest of the "path"
 * start a new line of Markdown structure -- are stripped outright.
 * @param {string} path
 * @returns {string}
 */
export function sanitizeFilePath(path) {
  const noControlChars = path.replace(/[\x00-\x1F\x7F]/g, '');
  return neutralizeMentions(noControlChars.replace(/`/g, 'ˋ')); // ` (grave accent) -> ˋ (modifier letter grave accent), visually similar, not a Markdown delimiter
}
