#!/bin/sh
# check_ai_defects_public_silence.sh -- fail if any vendor/scanner brand, or a
# first-party-authorship phrase, appears on a PUBLIC surface. The ai-defects gate is a
# CATEGORY, not a vendor: public docs name only the port ("ai-defects", "deeper
# verifier", "port wrapper", "pinned CLI in CI"). Wire this into CI so a brand string
# can never merge onto a public surface.
#
# Usage: check_ai_defects_public_silence.sh [ROOT]   (ROOT defaults to the repo root)
# Exit: 0 = clean, 1 = a denylisted string was found, 2 = a scan error (fail-closed).
set -eu

ROOT="${1:-}"
if [ -z "$ROOT" ]; then
  SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
  ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
fi

# Case-insensitive extended-regex denylist. 'skylos' is the known scanner brand; the
# phrases are mislabelled-product / first-party-authorship claims. 'our SAST' is anchored
# on its left with a start-or-non-alphanumeric boundary so ordinary second-person
# guidance ("your SAST policy") does not trip it. Extend the brand list in the private
# operator runbook, never in public docs.
PATTERN='skylos|we built this engine|(^|[^[:alnum:]])our SAST|auditor-ready SAST'

# Public surfaces in scope: EVERY root README* variant (not just README.md), references/**,
# the skill manifest, and workflow files (job names + public comments). set -- expands the
# README* glob; a variant that does not exist stays literal and is skipped by the -e test.
# This script lives in scripts/ (out of scope), so its own PATTERN never self-matches.
set -- "$ROOT"/README* "$ROOT/references" "$ROOT/SKILL.md" "$ROOT/.github/workflows"

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
hits=0

for p in "$@"; do
  [ -e "$p" ] || continue
  # -r recurse, -H always print filename (grep omits it for a single-file arg),
  # -I skip binary, -n line numbers, -i case-insensitive, -E regex. grep exits 0 on a
  # match, 1 on no match, >1 on a read/IO error -- an error must FAIL CLOSED, never read
  # as "no match".
  if grep -rHIniE -- "$PATTERN" "$p" >>"$tmp" 2>/dev/null; then
    hits=1
  else
    status=$?
    if [ "$status" -gt 1 ]; then
      echo "ai-defects public-silence check ERROR: cannot scan $p (grep exit $status)" >&2
      exit 2
    fi
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
