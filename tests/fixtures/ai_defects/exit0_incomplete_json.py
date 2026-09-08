#!/usr/bin/env python3
# ai-defects test fixture: exit 0 but writes an incomplete summary -> BLOCKED.
# The wrapper must trust the incomplete flag over the clean exit code.
import json
import os
import sys


def _run_dir(argv):
    for i, tok in enumerate(argv):
        if tok == "--run-dir" and i + 1 < len(argv):
            return argv[i + 1]
    return "."


if __name__ == "__main__":
    rd = _run_dir(sys.argv[1:])
    with open(os.path.join(rd, "ai-defects.json"), "w", encoding="utf-8") as f:
        json.dump({"incomplete": True, "reason": "partial scan"}, f)
    print("scan started")
    sys.exit(0)
