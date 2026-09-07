#!/bin/sh
# check_ai_defects_public_silence.sh -- fail if any vendor/scanner brand, or a
# first-party-authorship phrase, appears on a PUBLIC surface. The ai-defects gate is a
# CATEGORY, not a vendor: public docs name only the port ("ai-defects", "deeper
# verifier", "port wrapper", "pinned CLI in CI"). Wire this into CI so a brand string
# can never merge onto a public surface.
#
# Usage: check_ai_defects_public_silence.sh [ROOT]   (ROOT defaults to the repo root)
set -eu

ROOT="${1:-}"
if [ -z "$ROOT" ]; then
  SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
  ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
fi

# Case-insensitive extended-regex denylist. 'skylos' is the known scanner brand; the
# phrases are mislabelled-product / first-party-authorship claims. Extend the brand list
# in the private operator runbook, never in public docs.
PATTERN='skylos|we built this engine|our SAST|auditor-ready SAST'

# Public surfaces in scope: README*, references/**, the skill manifest, and workflow
# files (job names + public comments). Absent paths are skipped, not errors. This script
# lives in scripts/ (out of scope), so its own PATTERN never self-matches.
SCOPE="README.md references SKILL.md .github/workflows"

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
hits=0

for rel in $SCOPE; do
  p="$ROOT/$rel"
  [ -e "$p" ] || continue
  # -r recurse, -H always print filename (grep omits it for a single-file arg),
  # -I skip binary, -n line numbers, -i case-insensitive, -E regex.
  if grep -rHIniE -- "$PATTERN" "$p" >>"$tmp" 2>/dev/null; then
    hits=1
  fi
done

if [ "$hits" -ne 0 ]; then
  echo "ai-defects public-silence check FAILED: vendor/brand or authorship claim on a public surface:"
  cat "$tmp"
  echo "Use port language instead: 'ai-defects', 'deeper verifier', 'port wrapper', 'pinned CLI in CI'."
  exit 1
fi
echo "ai-defects public-silence check OK: no denylisted brand/authorship strings on public surfaces."
exit 0
