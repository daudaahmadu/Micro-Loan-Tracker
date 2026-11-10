# PostgreSQL migration notes

When `DATABASE_URL` is set, application account, loan, repayment, audit, bootstrap, and password-rotation operations use PostgreSQL. SQLite is retained only for explicitly configured non-production tests and local fixtures when `DATABASE_URL` is absent; production startup, bootstrap, and password rotation fail closed without `DATABASE_URL`; the application does not silently fall back after a PostgreSQL connection or query failure.

## Monetary profile and precision policy

Synthetic fixtures use positive decimal monetary values, including whole amounts, fractional amounts, zero-interest loans, high-but-valid interest rates, partial repayments, exact final repayments, overpayments, and concurrent repayment attempts. PostgreSQL stores monetary fields as unconstrained `NUMERIC` values with positive/range checks rather than binary floating-point columns. The application validates finite numeric input and preserves the supplied value through PostgreSQL parameters.

There is no silent rounding policy: no route or migration utility rounds, truncates, or converts a monetary value to a currency minor unit without an explicit product decision. Display formatting is presentation-only and shows at most two decimal places without converting through JavaScript `Number`. Reconciliation compares numeric values and row counts; any scale or value discrepancy must be reported and resolved explicitly.

## Synthetic migration safety

`scripts/reconcile-sqlite-to-postgres.js` requires `ALLOW_SYNTHETIC_MIGRATION=1`, a non-production `NODE_ENV`, an explicit `SOURCE_SQLITE_PATH`, and `DATABASE_URL`. Export uses a new destination file; restore additionally requires `ALLOW_SYNTHETIC_RESTORE=1` and validates the export shape. Default database paths and production mode are rejected. The utility never reads credentials or connects to production by itself.


## Configuration and readiness

Production requires `DATABASE_URL`, `REDIS_URL` (TLS `rediss://`), and a strong `SESSION_SECRET`; there is no SQLite fallback in production. Local test/dev runs may set `DATABASE_PATH` explicitly. `GET /health/ready` reports database and Redis readiness and returns HTTP 503 until both are available. Database errors are returned as generic temporary-unavailability responses without credentials or connection details.

## NGN decimal policy

Amounts and rates accept up to four decimal places and are never silently rounded or converted to a minor unit. PostgreSQL `NUMERIC` values remain decimal strings until Decimal arithmetic. Display formatting may explicitly show at most two decimal places; historical database values are not rewritten.

## Prototype and temporary resources

The UI is a visible prototype/demo. Local Redis, PostgreSQL, and SQLite fixtures are disposable and may expire or be removed between runs; they must not contain production data.
