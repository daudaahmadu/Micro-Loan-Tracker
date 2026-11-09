BEGIN;

CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'borrower' CHECK (role IN ('borrower', 'admin')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS loans (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES users(id),
    amount NUMERIC NOT NULL CHECK (amount > 0),
    interest_rate NUMERIC NOT NULL CHECK (interest_rate >= 0 AND interest_rate <= 100),
    interest_amount NUMERIC NOT NULL CHECK (interest_amount >= 0),
    total_repayment NUMERIC NOT NULL CHECK (total_repayment > 0),
    purpose TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Pending' CHECK (status IN ('Pending', 'Approved', 'Rejected')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS repayments (
    id BIGSERIAL PRIMARY KEY,
    loan_id BIGINT NOT NULL REFERENCES loans(id),
    user_id BIGINT NOT NULL REFERENCES users(id),
    amount NUMERIC NOT NULL CHECK (amount > 0),
    idempotency_key TEXT,
    payment_date TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT repayments_idempotency_key_length CHECK (idempotency_key IS NULL OR length(idempotency_key) <= 200)
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGSERIAL PRIMARY KEY,
    actor_user_id BIGINT REFERENCES users(id),
    actor_role TEXT,
    event_type TEXT NOT NULL,
    target_type TEXT,
    target_id BIGINT,
    metadata JSONB,
    ip_hash TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS loans_user_id_created_at_idx ON loans (user_id, created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS users_lower_email_uq ON users (lower(email));
CREATE INDEX IF NOT EXISTS repayments_loan_id_idx ON repayments (loan_id);
CREATE UNIQUE INDEX IF NOT EXISTS repayments_loan_idempotency_key_uq
    ON repayments (loan_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS repayments_user_id_payment_date_idx ON repayments (user_id, payment_date DESC);
CREATE INDEX IF NOT EXISTS audit_logs_event_type_created_at_idx ON audit_logs (event_type, created_at DESC);

COMMIT;
