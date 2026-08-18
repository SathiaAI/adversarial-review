# Change under review

## Requirements, acceptance criteria, and invariants
- `page(items, page_size, page_num)` returns exactly `page_size` items for a full page.
- Page `n` and page `n+1` must not overlap.

## Diff
```diff
--- a/core/paging.py
+++ b/core/paging.py
@@ -1,3 +1,6 @@
+def page(items, page_size, page_num):
+    start = page_num * page_size
+    end = start + page_size + 1
+    return items[start:end]
```

## Notes
`page_num` is 0-indexed. Callers concatenate successive pages when exporting.
