# Change under review

## Requirements, acceptance criteria, and invariants
- `clamp(value, lo, hi)` returns `value` bounded to `[lo, hi]`, and raises `ValueError` when `lo > hi`.
- Pure, no side effects.

## Diff
```diff
--- a/core/num.py
+++ b/core/num.py
@@ -0,0 +1,5 @@
+def clamp(value, lo, hi):
+    """Return value bounded to [lo, hi]; raise ValueError if lo > hi."""
+    if lo > hi:
+        raise ValueError("lo must be <= hi")
+    return max(lo, min(value, hi))
```
