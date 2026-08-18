# Change under review

## Requirements, acceptance criteria, and invariants
- `total_price(items)` sums `unit_price * qty` over items.
- This change renames a local loop variable and adds a docstring; observable behavior must be identical.

## Diff
```diff
--- a/cart/pricing.py
+++ b/cart/pricing.py
@@ -1,2 +1,3 @@
 def total_price(items):
-    return sum(x.unit_price * x.qty for x in items)
+    """Sum unit_price * qty over items."""
+    return sum(item.unit_price * item.qty for item in items)
```
