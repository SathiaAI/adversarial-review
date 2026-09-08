#!/usr/bin/env python3
# ai-defects test fixture: verify could not complete (exit 2 -> BLOCKED).
import sys

if __name__ == "__main__":
    print("could not resolve environment")
    sys.exit(2)
