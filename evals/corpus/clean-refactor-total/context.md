# Change under review

## Requirements, acceptance criteria, and invariants
- `total_price` sums `unit_price * qty` over items. This change only renames a local and
  adds a docstring — behavior must be identical.

## Diff
```diff
--- a/cart/pricing.py
+++ b/cart/pricing.py
@@ -1,2 +1,3 @@
-def total_price(items):
-    return sum(x.unit_price * x.qty for x in items)
+def total_price(items):
+    """Sum unit_price * qty over items."""
+    return sum(item.unit_price * item.qty for item in items)
```

## Notes
Pure rename + docstring; the comprehension is otherwise unchanged. No defect.
