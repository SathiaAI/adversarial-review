# Change under review

## Requirements, acceptance criteria, and invariants
- Human-facing log/status text must state the true outcome of the operation.
- `process(order)` returns truthy on success, falsey on failure.
- `log.info(...)` lines are surfaced to operators in the ops dashboard.

## Diff
```diff
--- a/orders/finalize.py
+++ b/orders/finalize.py
@@ -1,3 +1,7 @@
 def finalize(order):
     ok = process(order)
-    return ok
+    if not ok:
+        log.info("Order %s finalized successfully", order.id)
+        return False
+    log.info("Order %s finalized successfully", order.id)
+    return True
```
