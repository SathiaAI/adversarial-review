#!/usr/bin/env python3
# ai-defects test fixture: spawns a worker that writes <run-dir>/child-marker after a
# delay, then the parent hangs. If the wrapper kills only the immediate process on
# timeout, the worker survives and writes the marker; a process-group tree-kill takes the
# worker down too (so the marker never appears).
import os
import subprocess
import sys
import time


def _run_dir(argv):
    for i, tok in enumerate(argv):
        if tok == "--run-dir" and i + 1 < len(argv):
            return argv[i + 1]
    return "."


if __name__ == "__main__":
    rd = _run_dir(sys.argv[1:])
    marker = os.path.join(rd, "child-marker")
    code = "import time\ntime.sleep(3)\nopen(%r, 'w').write('leaked')" % marker
    subprocess.Popen([sys.executable, "-c", code])
    time.sleep(10)
    sys.exit(0)
