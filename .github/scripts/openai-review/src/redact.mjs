/**
 * Best-effort secret-shape detection, defense-in-depth only.
 *
 * This is explicitly NOT a guarantee: it matches known credential shapes
 * and will miss anything that doesn't match a known pattern (an opaque
 * internal token format, for example). It is not a substitute for never
 * committing secrets, and must not be described to anyone as a promise of
 * safety.
 *
 * When a match is found, the file is excluded from the OpenAI request
 * entirely -- never redacted-and-sent, since redaction of the matched
 * span alone still transmits the surrounding context and relies on the
 * pattern coverage being perfect, which it isn't.
 */

const SECRET_PATTERNS = [
  { name: 'AWS access key ID', regex: /AKIA[0-9A-Z]{16}/ },
  { name: 'GitHub token', regex: /gh[pousr]_[A-Za-z0-9]{36,}/ },
  { name: 'OpenAI API key', regex: /sk-[A-Za-z0-9]{20,}/ },
  { name: 'Slack token', regex: /xox[baprs]-[A-Za-z0-9-]{10,}/ },
  { name: 'PEM private key block', regex: /-----BEGIN [A-Z ]*PRIVATE KEY-----/ },
  { name: 'generic bearer token', regex: /\bbearer\s+[A-Za-z0-9._-]{20,}/i },
];

/**
 * @param {string} patchText
 * @returns {string | null} the matched pattern's name, or null if nothing matched
 */
export function detectSecretShape(patchText) {
  for (const { name, regex } of SECRET_PATTERNS) {
    if (regex.test(patchText)) {
      return name;
    }
  }
  return null;
}
