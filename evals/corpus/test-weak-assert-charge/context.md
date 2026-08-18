# Change under review

## Requirements, acceptance criteria, and invariants
- `charge_customer(cust, amount)` calls `billing.gateway.charge(amount)`, returns its result, and raises `PaymentError` on a falsey result.
- A test for it must assert the observable outcome (the amount charged and the failure path), which are the behaviors this test is responsible for.

## Diff
```diff
--- a/tests/test_billing.py
+++ b/tests/test_billing.py
@@ -0,0 +1,9 @@
+from billing import charge_customer
+from billing.models import Customer
+
+
+def test_charge_customer(mocker):
+    cust = Customer(id=1)
+    gw = mocker.patch("billing.gateway.charge", return_value=True)
+    charge_customer(cust, 100)
+    assert gw.called
```

## Surrounding code
`mocker.patch` replaces `billing.gateway.charge`. `Customer(id=1)` is a valid domain object; `charge_customer` and `Customer` are imported above.
