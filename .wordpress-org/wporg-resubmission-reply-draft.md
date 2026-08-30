DRAFT ONLY — for Simon's review. Not sent. Use the "Add your plugin" page's
upload-with-comment feature (confirmed working 2026-08-27): attach
.wordpress-org/vcns-security-automation-manager-v2.9.24.zip and paste this
text as the accompanying comment, in one action, rather than a separate
email reply.

---

Thank you for the review.

The DNS Made Easy and INWX external-service entries link Terms/Privacy documents on a different domain than the API hostname itself (dnsmadeeasy.com/domrobot.com vs. digicert.com/inwx.com) — that's not a gap, it's the only correct link in each case. Verified directly: dnsmadeeasy.com has no legal pages of its own (checked six candidate paths, all 404; its own homepage's footer links to the exact two DigiCert URLs already in our disclosure). domrobot.com has no A/AAAA record at all — only the api. subdomain resolves, and visiting its root redirects straight to inwx.com/en/offer/api. DomRobot isn't a separate company; it's INWX's own branded name for this API (their own GitHub org publishes and maintains its client libraries directly: github.com/inwx/php-client, python-client, java-client, ruby-client). Made all of this explicit in the readme text itself.

Same reasoning for the GitHub Pages update-manifest: *.github.io has no terms separate from github.com, so the linked Terms of Service and Privacy Statement are GitHub's own, not a mismatch.

The escaping citations (Table_Query::sort_header()/pagination(), Risk_Badge::render(), and the three heuristic HTML-escaping lines) are all lines that already carry our own inline justification comments, several quoted back verbatim in your examples — nothing new there.

Package: vcns-security-automation-manager-v2.9.24.zip

Please let me know if anything else needs attention.

Simon Jackson
VCNS Tech Ltd
