# Change under review

## Requirements, acceptance criteria, and invariants
- Human-facing log/status text must state the TRUE outcome. A failure branch must not
  claim success.

## Diff
```diff
--- a/orders/finalize.py
+++ b/orders/finalize.py
@@ -10,8 +10,12 @@ def finalize(order):
     ok = process(order)
-    return ok
+    if not ok:
+        log.info("Order %s finalized successfully", order.id)
+        return False
+    log.info("Order %s finalized successfully", order.id)
+    return True
```

## Notes
`log.info(...)` lines are surfaced to operators in the ops dashboard. The `if not ok`
branch emits the success sentence — an inverted statement about the real state.
