# PostgreSQL migration notes

When `DATABASE_URL` is set, application account, loan, repayment, audit, bootstrap, and password-rotation operations use PostgreSQL. SQLite is retained only for tests and local fixtures when `DATABASE_URL` is absent; the application does not silently fall back after a PostgreSQL connection or query failure.

## Monetary profile and precision policy

Synthetic fixtures use positive decimal monetary values, including whole amounts, fractional amounts, zero-interest loans, high-but-valid interest rates, partial repayments, exact final repayments, overpayments, and concurrent repayment attempts. PostgreSQL stores monetary fields as unconstrained `NUMERIC` values with positive/range checks rather than binary floating-point columns. The application validates finite numeric input and preserves the supplied value through PostgreSQL parameters.

There is no silent rounding policy: no route or migration utility rounds, truncates, or converts a monetary value to a currency minor unit without an explicit product decision. Display formatting (`toLocaleString`) is presentation-only. Reconciliation compares numeric values and row counts; any scale or value discrepancy must be reported and resolved explicitly.

## Synthetic migration safety

`scripts/reconcile-sqlite-to-postgres.js` requires `ALLOW_SYNTHETIC_MIGRATION=1`, a non-production `NODE_ENV`, an explicit `SOURCE_SQLITE_PATH`, and `DATABASE_URL`. Export uses a new destination file; restore additionally requires `ALLOW_SYNTHETIC_RESTORE=1` and validates the export shape. Default database paths and production mode are rejected. The utility never reads credentials or connects to production by itself.
