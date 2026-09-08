#!/usr/bin/env python3
# ai-defects test fixture: hangs so the wrapper watchdog fires (timeout -> BLOCKED).
import sys
import time

if __name__ == "__main__":
    time.sleep(30)
    sys.exit(0)
