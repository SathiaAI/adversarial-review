"""adversarial-review: multi-model adversarial code review with a deterministic,
machine-computed release verdict. Console entry points: ar-panel, ar-gate,
ar-aggregate. The modules are also runnable directly from a skills folder
(python scripts/panel.py ...) — same files, two distribution surfaces.

Import caveat (deliberate tradeoff): importing these modules prepends their own
directory to sys.path so the siblings resolve identically in both surfaces. The
ar-* commands are short-lived CLI processes, which contains that pollution; do
not embed these modules as a library inside a process that also imports an
unrelated top-level `panel`, `gate`, or `aggregate` package."""
__version__ = "0.2.0"
