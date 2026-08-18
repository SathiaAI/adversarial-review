# Change under review

## Requirements, acceptance criteria, and invariants
- `page(items, page_size, page_num)` returns exactly `page_size` items for a full page.
- `page_num` is 0-indexed; page `n` and page `n+1` must not overlap.
- Callers concatenate successive pages when exporting.

## Diff
```diff
--- a/core/paging.py
+++ b/core/paging.py
@@ -0,0 +1,4 @@
+def page(items, page_size, page_num):
+    start = page_num * page_size
+    end = start + page_size + 1
+    return items[start:end]
```
