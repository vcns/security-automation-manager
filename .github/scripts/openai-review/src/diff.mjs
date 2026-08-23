/**
 * Diff retrieval and completeness checking for Stage 2.
 *
 * GitHub's "list pull request files" endpoint can return a file entry with
 * no `patch` field at all (binary files, or a diff GitHub's own internal
 * size threshold won't render), and can also return a `patch` string that
 * looks present but is truncated for some other GitHub-side reason -- a
 * present patch is therefore not automatically trusted as complete. Every
 * file that can't be confirmed complete is excluded and reported, never
 * silently dropped or silently treated as fully reviewed.
 */

const DEFAULT_EXCLUDE_PATTERNS = [
  // Dependency lockfiles -- large, mechanical, nothing to review.
  '**/package-lock.json',
  '**/composer.lock',
  '**/yarn.lock',
  '**/pnpm-lock.yaml',
  // Vendored/third-party code, never authored in this repo.
  'vendor/**',
  'node_modules/**',
  // Generated or bundled build output.
  '**/*.min.js',
  '**/*.min.css',
  'dist/**',
  'build/**',
  // Binary/asset files with nothing textual to review.
  '**/*.png', '**/*.jpg', '**/*.jpeg', '**/*.gif', '**/*.webp', '**/*.ico',
  '**/*.woff', '**/*.woff2', '**/*.ttf', '**/*.eot',
  '**/*.wasm', '**/*.zip', '**/*.tar', '**/*.gz',
];

/**
 * Minimal glob matcher supporting `**` (a leading globstar segment
 * followed by a slash matches zero or more directories, so it matches
 * both a nested path and a root-level bare filename; a trailing or
 * standalone globstar matches everything that follows), `*` (anything
 * except a path separator), and literal segments -- enough for the
 * exclusion patterns above without adding a dependency. (Note for anyone
 * editing this comment: never write the literal two-character glob token
 * "double-star-slash" directly in a /* *​/ block comment -- its `/` closes
 * the comment early, corrupting everything after it. Describe it in
 * words, as done here, or keep it inside a string/regex literal instead.)
 *
 * Regex-special characters other than `*` are escaped first; `*` is
 * deliberately left alone by that escaping step (it is not in the escaped
 * character class below) so a single subsequent regex, matched against
 * the ORIGINAL pattern positions via a replacer function (not a chained
 * string substitution), can identify and translate each glob token
 * exactly once, with no risk of one substitution's output being
 * re-matched by a later step.
 * @param {string} pattern
 * @param {string} path
 * @returns {boolean}
 */
export function globMatch(pattern, path) {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  const regexBody = escaped.replace(/\*\*\/|\*\*|\*/g, (token) => {
    if (token === '**/') return '(?:.*/)?';
    if (token === '**') return '.*';
    return '[^/]*';
  });
  return new RegExp(`^${regexBody}$`).test(path);
}

/**
 * @param {string} filename
 * @param {string[]} [extraExcludePatterns]
 * @returns {boolean}
 */
export function isExcludedByPattern(filename, extraExcludePatterns = []) {
  return [...DEFAULT_EXCLUDE_PATTERNS, ...extraExcludePatterns].some((pattern) => globMatch(pattern, filename));
}

/**
 * Counts added/removed lines in a unified diff patch, excluding only `@@`
 * hunk headers.
 *
 * Deliberately does NOT try to skip `+++`/`---`-prefixed lines as file
 * headers: GitHub's "list pull request files" `patch` field is a per-file
 * fragment that starts directly at the first `@@` hunk header -- it never
 * includes the `--- a/path`/`+++ b/path` preamble a raw `git diff` or
 * `diff -u` would (the file identity is already given by this same API
 * response's own `filename` field). An earlier version of this function
 * skipped any line starting with the literal three-character sequence
 * `+++` or `---`, which silently miscounted genuine added/removed content
 * lines that happen to start with that sequence (e.g. an added line whose
 * code content itself begins with `++`, or a removed line beginning with
 * `--`) -- falsely flagging an otherwise-complete patch as incomplete.
 *
 * @param {string} patch
 * @returns {{additions: number, deletions: number}}
 */
export function countPatchLines(patch) {
  let additions = 0;
  let deletions = 0;
  for (const line of patch.split('\n')) {
    if (line.startsWith('@@')) continue; // hunk header
    if (line.startsWith('+')) additions++;
    else if (line.startsWith('-')) deletions++;
    // context lines and "\ No newline at end of file" markers: neither
  }
  return { additions, deletions };
}

/**
 * Classifies one file entry from the GitHub "list pull request files"
 * response as included or excluded, with a precise reason.
 *
 * @param {object} file - one entry from GET .../pulls/{n}/files
 * @param {string[]} [extraExcludePatterns]
 * @returns {{included: true, file: object} | {included: false, filename: string, reason: string}}
 */
export function classifyFile(file, extraExcludePatterns = []) {
  // Reviewed regardless of status (added/removed/modified/renamed/copied/
  // changed) -- "changed files only" means every file GitHub reports as
  // part of this PR's diff, not merely the modified/added subset. A
  // security-relevant removal (e.g. deleting an authorisation check) is
  // exactly the kind of change that must not be excluded here. Only a
  // genuinely content-free status is skipped.
  if (file.status === 'unchanged') {
    return { included: false, filename: file.filename, reason: 'status is "unchanged", nothing to review' };
  }
  if (isExcludedByPattern(file.filename, extraExcludePatterns)) {
    return { included: false, filename: file.filename, reason: 'excluded by file-type/path rule' };
  }
  if (!file.patch) {
    return { included: false, filename: file.filename, reason: 'no diff available (binary file, or too large for GitHub to render)' };
  }
  const counted = countPatchLines(file.patch);
  if (counted.additions !== file.additions || counted.deletions !== file.deletions) {
    return {
      included: false,
      filename: file.filename,
      reason: `patch appears incomplete (parsed +${counted.additions}/-${counted.deletions} vs. GitHub-reported +${file.additions}/-${file.deletions})`,
    };
  }
  return { included: true, file };
}

/**
 * Fetches every page of a pull request's changed files via the provided
 * fetch function, applies exclusion/completeness rules, and enforces the
 * byte and file-count ceilings. Never assumes the first page is the whole
 * PR.
 *
 * @param {(page: number) => Promise<object[]>} fetchFilesPage - returns one page (per_page=100) of file entries; empty array signals no more pages
 * @param {{maxBytes: number, maxFiles: number, extraExcludePatterns?: string[]}} limits
 * @returns {Promise<{status: 'ok', included: object[], excluded: {filename: string, reason: string}[]} | {status: 'too_large', reason: string, included: object[], excluded: {filename: string, reason: string}[]}>}
 */
export async function collectDiff(fetchFilesPage, limits) {
  const included = [];
  const excluded = [];
  let page = 1;

  for (;;) {
    const batch = await fetchFilesPage(page);
    if (!batch || batch.length === 0) break;

    for (const file of batch) {
      const classified = classifyFile(file, limits.extraExcludePatterns ?? []);
      if (classified.included) {
        included.push(classified.file);
      } else {
        excluded.push({ filename: classified.filename, reason: classified.reason });
      }
    }
    page += 1;
  }

  if (included.length > limits.maxFiles) {
    return { status: 'too_large', reason: `${included.length} reviewable files exceeds the ${limits.maxFiles}-file ceiling`, included, excluded };
  }

  const totalBytes = included.reduce((sum, file) => sum + (file.patch?.length ?? 0), 0);
  if (totalBytes > limits.maxBytes) {
    return { status: 'too_large', reason: `${totalBytes} bytes of diff exceeds the ${limits.maxBytes}-byte ceiling`, included, excluded };
  }

  return { status: 'ok', included, excluded };
}
