# Change under review

## Requirements, acceptance criteria, and invariants
- A logged-in user may read **only their own** invoices via `GET /invoices/<id>`.
- Invariant: no endpoint returns a record belonging to another tenant/user.
- `current_user` is the authenticated principal; `Invoice.user_id` is the owner.

## Diff
```diff
--- a/api/invoices.py
+++ b/api/invoices.py
@@ -38,6 +38,12 @@ def list_invoices():
     invoices = Invoice.query.filter_by(user_id=current_user.id).all()
     return jsonify([i.to_dict() for i in invoices])

+@app.route("/invoices/<int:invoice_id>")
+@login_required
+def get_invoice(invoice_id):
+    inv = Invoice.query.get_or_404(invoice_id)
+    return jsonify(inv.to_dict())
+
```

## Surrounding code the change depends on
`Invoice` rows carry `user_id`. The list endpoint (unchanged, above) filters by
`current_user.id`; the new detail endpoint does not.
