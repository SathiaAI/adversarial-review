# Change under review

## Requirements, acceptance criteria, and invariants
- A logged-in user may read only their own invoices via `GET /invoices/<id>`.
- Invariant: no endpoint returns a record belonging to another user or tenant.
- `current_user` is the authenticated principal; every `Invoice` row has a `user_id` owner.

## Diff
```diff
--- a/api/invoices.py
+++ b/api/invoices.py
@@ -3,3 +3,10 @@
 def list_invoices():
     invoices = Invoice.query.filter_by(user_id=current_user.id).all()
     return jsonify([i.to_dict() for i in invoices])
+
+
+@app.route("/invoices/<int:invoice_id>")
+@login_required
+def get_invoice(invoice_id):
+    inv = Invoice.query.get_or_404(invoice_id)
+    return jsonify(inv.to_dict())
```

## Surrounding code
`Invoice.query.get_or_404(id)` fetches by primary key only. `current_user.id` is the authenticated principal's id.
