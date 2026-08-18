# Change under review

## Requirements, acceptance criteria, and invariants
- `clamp(value, lo, hi)` returns `value` bounded to `[lo, hi]`; raises `ValueError` when
  `lo > hi`. Pure, no side effects.

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
--- a/tests/test_num.py
+++ b/tests/test_num.py
@@ -0,0 +1,8 @@
+import pytest
+from core.num import clamp
+def test_clamp():
+    assert clamp(5, 0, 10) == 5
+    assert clamp(-1, 0, 10) == 0
+    assert clamp(11, 0, 10) == 10
+    with pytest.raises(ValueError):
+        clamp(1, 10, 0)
```

## Notes
Correct boundary handling and the error path are both tested. This case carries no defect.
