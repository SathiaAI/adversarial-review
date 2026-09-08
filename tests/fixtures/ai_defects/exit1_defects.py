#!/usr/bin/env python3
# ai-defects test fixture: a completed verify that found defects (exit 1 -> FAIL).
import sys

if __name__ == "__main__":
    print("found 2 phantom references")
    sys.exit(1)
