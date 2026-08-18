# Change under review

## Requirements, acceptance criteria, and invariants
- `charge_customer(cust, amount)` must charge exactly `amount` and propagate gateway
  failures (returns False / raises) — the test must assert the observable outcome and the
  failure path, not merely that a mock ran.

## Diff
```diff
--- a/tests/test_billing.py
+++ b/tests/test_billing.py
@@ -0,0 +1,6 @@
+def test_charge_customer(mocker):
+    gw = mocker.patch("billing.gateway.charge", return_value=True)
+    charge_customer(cust, 100)
+    assert gw.called
```

## Surrounding code
`charge_customer` calls `billing.gateway.charge(amount)` and returns its result; on a
falsey result it should raise `PaymentError`. None of that is asserted; the amount passed
to the gateway is never checked, and the failure path is untested.
