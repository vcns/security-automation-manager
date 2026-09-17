# SAM Admin Table UX Standard

## Purpose

SAM's admin tables evolved independently across many phases and ended up with three incompatible column-width strategies: natural (no CSS at all), `table-layout: fixed` + hand-tuned `nth-child()` percentages, and `table-layout: fixed` + hand-tuned `nth-child()` pixel widths. Semantically identical columns (Status, Surface, Count, Date/Time, Actions) were sized differently page to page, and every list-shaped table reinvented its own "let one column flex" math. This document is the standard the repository-wide table migration established, so a future feature doesn't reintroduce the same problem one table at a time.

This is a layout/CSS standard only. It says nothing about security behaviour, stored data, decision logic, or workflow design.

## Semantic column roles

Column sizing is driven by what a column *contains*, never by its ordinal position. Add the matching class to both the `<th>` and every corresponding `<td>` in that column -- CSS `:nth-child()` cannot express column meaning, so the template has to.

| Class | Contains | Behaviour |
|---|---|---|
| `wp-sam-col-compact` | IDs, short flags | `width: 1%; white-space: nowrap` -- only the width the content needs |
| `wp-sam-col-count` | Numeric counts | Same as compact, right-aligned by default |
| `wp-sam-col-status` | Status/risk/severity badges (Protected, Learning, Active, High, ...) | Same as compact -- content-sized, no wrap |
| `wp-sam-col-surface` | Frontend / Admin / Login / API | Same as compact -- no wrap |
| `wp-sam-col-datetime` | First Seen, Last Seen, Updated, Expires | `min-width: 9em; white-space: nowrap` |
| `wp-sam-col-primary` | The row's main identifier: host, detector, control, dependency, cert/domain, item name | `min-width: 12em`, flexible |
| `wp-sam-col-description` | Reason, classification, consequence, explanation | `min-width: 16em`, flexible -- usually the widest column |
| `wp-sam-col-technical` | URLs, hashes, CSP sources, directives, fingerprints, evidence strings | `min-width: 12em`, `overflow-wrap: anywhere; word-break: break-word` -- allowed to break safely |
| `wp-sam-col-actions` | View / Manage / Review / Delete / Release | Same as compact -- content-sized, no wrap |

Values above are starting points, not a mandate for identical widths everywhere -- the goal is consistency of *behaviour*, not mathematical uniformity. A table with unusually long content in one column may raise just that column's `min-width` with a small, table-scoped CSS override (e.g. `.wp-sam-profiles-table .wp-sam-automation-mode { max-width: 100% }` already does this for one inner control, not the column itself).

A table-specific class (e.g. `wp-sam-drift-table`) should describe *that table* -- it stays as the table's identity/JS-hook class, but should not itself carry column-width rules once migrated, and must never be combined with another table's class merely to inherit its widths.

## Wrapping policy

**Never wrap:** short status values, severity/risk values, surface names, short counts, dates/times, simple action links/buttons -- these all use `white-space: nowrap` via their column class.

**Wrap safely when needed:** URLs, hostnames, source values, hashes, directives, long classifications, explanations, reasons, evidence, descriptions -- `wp-sam-col-technical` uses `overflow-wrap: anywhere` so one long token can't force the rest of the table off-screen; `wp-sam-col-primary`/`wp-sam-col-description` wrap normally at word boundaries.

## `table-layout: fixed`

Not used by default. SAM tables use the browser's natural/automatic layout plus the semantic column classes above -- `width: 1%; white-space: nowrap` is what makes a compact/status/surface/count/actions column shrink to its own content under auto layout, and `min-width` (never paired with a `max-width` that would force overflow) is what gives a flexible column a sensible floor. Neither needs `fixed` to work, and auto layout means an unusually long value in one column doesn't have to be pre-computed into a percentage that adds up to 100%.

`table-layout: fixed` is only acceptable with a documented, table-specific UX reason (a comment directly above the rule explaining it) -- for example, a table whose row count is large enough that fixed layout's single-pass rendering performance genuinely matters. If you can't write that comment, use auto layout.

## Responsive / overflow policy

Wrap every table in `<div class="wp-sam-table-wrap"><table class="widefat striped wp-sam-table ...">`. `.wp-sam-table-wrap` contains horizontal scrolling to that one table (`overflow-x: auto; max-width: 100%`) -- a long URL, hash, or evidence string scrolls its own table, it never pushes the whole wp-admin page wider than the viewport. Do not convert a table into cards on mobile as part of a routine table update; that's a larger UX decision, not a default.

## Action-column policy

**Simple actions** (View, Manage, Review, Delete, Release -- one link or one button, or a short, fixed set of them): use `wp-sam-col-actions`, content-sized, normally right-side.

**Complex interactive controls** (a select + text input + several buttons; a reason field plus an approve/reject workflow; multiple large form controls in one row) are a genuine mini-workflow, not an "Actions column that needs to be wider" problem. Don't keep growing the column -- note it as follow-on UX debt (row expansion, `<details>`, a modal, a dedicated review page, or an existing SAM workflow are the usual candidates) rather than solving it with an ever-wider column. Known cases as of the 2.10.x table migration: Baseline & Drift's Drift Actions, Advanced Intelligence's Campaigns Actions, Continuous Intelligence's Identities "Decision" cell, Traffic Controls' Blocks Actions and Custom Rules Actions, Scripts External's "Expected SRI" cell, and CSP Profiles' Bypass-Best-Practices/Actions cells.

## Alignment

- Primary/description values: left.
- Status badges: left, unless there's a compelling established reason otherwise.
- Counts: right, via `wp-sam-col-count`'s own default -- override per-table only when right-alignment doesn't actually help scanability for that specific count.
- Dates: consistent across tables (left, via `wp-sam-col-datetime`).
- Headers use the same column class as their body cells, so a header can never visually drift from the column it describes.

## Prohibited patterns

- New `th:nth-child()`/`td:nth-child()` width rules. If semantic markup genuinely cannot express a requirement, the exception needs an inline comment explaining why -- this should be rare, not the default.
- `widefat fixed` as an unexplained default. Justify `fixed` per the section above, or drop it.
- Combining two different tables' own identity classes on one `<table>` to inherit width behaviour from the other (the old `.wp-sam-blocks-table`/`.wp-sam-violations-table` pattern). Shared behaviour belongs in the semantic column classes, not in another table's class.
- Arbitrary fixed pixel/percentage widths reintroduced "to make the numbers add up to 100%" under `table-layout: fixed`.

## Accessibility

Preserve genuine `<table>`/`<thead>`/`<tbody>`/`<th>` semantics; never rely on colour alone for status (pair a badge with its text); keep focusable actions keyboard-reachable; a `.wp-sam-table-wrap` scroll container must not make keyboard navigation impractical; never hide information solely to make a table fit narrower.
