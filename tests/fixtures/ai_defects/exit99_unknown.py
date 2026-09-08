#!/usr/bin/env python3
# ai-defects test fixture: an out-of-taxonomy exit code (99 -> BLOCKED, fail-closed).
import sys

if __name__ == "__main__":
    sys.exit(99)
