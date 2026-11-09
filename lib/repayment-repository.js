function toNumber(value) {
    const number = Number(value);
    return Number.isFinite(number) ? number : null;
}

function normalizeIdempotencyKey(value) {
    if (value === undefined || value === null || value === "") return null;
    if (typeof value !== "string" || value.length > 200) {
        throw new Error("Invalid idempotency key.");
    }
    return value;
}

function createRepaymentRepository({ sqliteDb = null, postgres = null } = {}) {
    if (postgres) {
        return {
            async record({ loanId, userId, amount, idempotencyKey = null }) {
                const key = normalizeIdempotencyKey(idempotencyKey);
                return postgres.transaction(async client => {
                    const loanResult = await client.query(
                        "SELECT id, user_id, status, total_repayment FROM loans WHERE id = $1 AND user_id = $2 FOR UPDATE",
                        [loanId, userId]
                    );
                    if (!loanResult.rowCount) return { ok: false, reason: "not_found" };
                    const loan = loanResult.rows[0];
                    if (loan.status !== "Approved") return { ok: false, reason: "not_approved", loan };
                    if (key) {
                        const existing = await client.query(
                            "SELECT id, loan_id, user_id, amount, payment_date FROM repayments WHERE idempotency_key = $1",
                            [key]
                        );
                        if (existing.rowCount) {
                            const row = existing.rows[0];
                            if (String(row.loan_id) !== String(loanId) || String(row.user_id) !== String(userId)) {
                                return { ok: false, reason: "idempotency_conflict" };
                            }
                            return { ok: true, idempotent: true, repayment: row, remainingBalance: null };
                        }
                    }
                    const paidResult = await client.query(
                        "SELECT COALESCE(SUM(amount), 0) AS total_paid FROM repayments WHERE loan_id = $1 AND user_id = $2",
                        [loanId, userId]
                    );
                    const totalPaid = toNumber(paidResult.rows[0].total_paid) || 0;
                    const totalRepayment = toNumber(loan.total_repayment);
                    const repaymentAmount = toNumber(amount);
                    const remainingBalance = totalRepayment - totalPaid;
                    if (repaymentAmount === null || repaymentAmount <= 0) return { ok: false, reason: "invalid_amount" };
                    if (repaymentAmount > remainingBalance) return { ok: false, reason: "overpayment", remainingBalance };
                    const inserted = await client.query(
                        `INSERT INTO repayments (loan_id, user_id, amount, idempotency_key)
                         VALUES ($1, $2, $3, $4)
                         RETURNING id, loan_id, user_id, amount, payment_date`,
                        [loanId, userId, repaymentAmount, key]
                    );
                    return {
                        ok: true,
                        idempotent: false,
                        repayment: inserted.rows[0],
                        remainingBalance: remainingBalance - repaymentAmount
                    };
                });
            }
        };
    }
    if (!sqliteDb) throw new Error("A SQLite database or PostgreSQL database is required.");
    return {
        record({ loanId, userId, amount }) {
            const loan = sqliteDb.prepare("SELECT * FROM loans WHERE id = ? AND user_id = ?").get(loanId, userId);
            if (!loan) return { ok: false, reason: "not_found" };
            if (loan.status !== "Approved") return { ok: false, reason: "not_approved", loan };
            const paid = sqliteDb.prepare("SELECT COALESCE(SUM(amount), 0) AS total_paid FROM repayments WHERE loan_id = ? AND user_id = ?").get(loanId, userId);
            const remainingBalance = loan.total_repayment - paid.total_paid;
            if (amount > remainingBalance) return { ok: false, reason: "overpayment", remainingBalance };
            sqliteDb.prepare("INSERT INTO repayments (loan_id, user_id, amount) VALUES (?, ?, ?)").run(loanId, userId, amount);
            return { ok: true, idempotent: false, remainingBalance: remainingBalance - amount };
        }
    };
}

module.exports = { createRepaymentRepository, normalizeIdempotencyKey };
