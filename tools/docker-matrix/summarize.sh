#!/usr/bin/env bash
# Prints a Markdown table of every environment's checks from
# results/*/checks.tsv: one row per environment, one column per check.
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
cols=(a b c d e1 e2 e3 e-editor e-grid f g)

printf '| Environment |'
printf ' %s |' "${cols[@]}"
printf '\n|---|'
printf -- '---|%.0s' "${cols[@]}"
printf '\n'

for f in "$DIR"/results/*/checks.tsv; do
	[ -e "$f" ] || continue
	env="$(basename "$(dirname "$f")")"
	wp="$(sed -n 's/^wordpress=//p' "$(dirname "$f")/env.txt" 2>/dev/null)"
	php="$(sed -n 's/^php=//p' "$(dirname "$f")/env.txt" 2>/dev/null)"
	printf '| %s (WP %s, PHP %s) |' "$env" "${wp:-?}" "${php:-?}"
	for c in "${cols[@]}"; do
		s="$(awk -F'\t' -v c="$c" '$1 == c { print $2 }' "$f" | tail -1)"
		if [ -z "$s" ] && [[ "$c" == e* ]]; then
			s="$(awk -F'\t' '$1 == "e" { print $2 }' "$f" | tail -1)"
		fi
		printf ' %s |' "${s:-not run}"
	done
	printf '\n'
done
