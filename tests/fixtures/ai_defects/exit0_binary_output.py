#!/usr/bin/env python3
# ai-defects test fixture: emits a non-UTF-8 byte on stdout, then exits 0. The wrapper
# must decode child output leniently (never crash into a FAIL) and record PASS on the
# clean exit code.
import sys

if __name__ == "__main__":
    sys.stdout.buffer.write(b"\xff\xfe scan ok (not utf-8)\n")
    sys.stdout.flush()
    sys.exit(0)
