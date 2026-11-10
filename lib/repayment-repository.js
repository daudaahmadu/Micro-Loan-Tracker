const { Decimal, decimalString, subtract } = require("./decimal");
function normalizeIdempotencyKey(value) { if (value === undefined || value === null || value === "") return null; if (typeof value !== "string" || value.length > 200) throw new Error("Invalid idempotency key."); return value; }
function createRepaymentRepository({ sqliteDb = null, postgres = null, auditIpHash = () => null } = {}) {
    if (postgres) return { async record({ loanId, userId, amount, idempotencyKey = null, req = null }) {
        const key = normalizeIdempotencyKey(idempotencyKey); const repaymentAmount = decimalString(String(amount), { positive: true, allowZero: false });
        return postgres.transaction(async client => {
            const loanResult = await client.query("SELECT id, user_id, status, total_repayment FROM loans WHERE id = $1 AND user_id = $2 FOR UPDATE", [loanId, userId]);
            if (!loanResult.rowCount) return { ok: false, reason: "not_found" }; const loan = loanResult.rows[0];
            if (loan.status !== "Approved") return { ok: false, reason: "not_approved", loan };
            if (!repaymentAmount) return { ok: false, reason: "invalid_amount" };
            if (key) { const existing = await client.query("SELECT id, loan_id, user_id, amount, payment_date FROM repayments WHERE idempotency_key = $1", [key]); if (existing.rowCount) { const row = existing.rows[0]; if (String(row.loan_id) !== String(loanId) || String(row.user_id) !== String(userId)) return { ok: false, reason: "idempotency_conflict" }; await client.query("INSERT INTO audit_logs (actor_user_id, actor_role, event_type, target_type, target_id, metadata, ip_hash) VALUES ($1, 'borrower', 'repayment.create', 'repayment', $2, $3::jsonb, $4)", [userId, row.id, JSON.stringify({ loanId, idempotent: true }), auditIpHash(req)]); return { ok: true, idempotent: true, repayment: row, remainingBalance: null }; } }
            const paid = (await client.query("SELECT COALESCE(SUM(amount), 0) AS total_paid FROM repayments WHERE loan_id = $1 AND user_id = $2", [loanId, userId])).rows[0].total_paid;
            const remaining = new Decimal(String(loan.total_repayment)).minus(String(paid));
            if (new Decimal(repaymentAmount).gt(remaining)) return { ok: false, reason: "overpayment", remainingBalance: remaining.toString() };
            const inserted = (await client.query("INSERT INTO repayments (loan_id, user_id, amount, idempotency_key) VALUES ($1, $2, $3, $4) RETURNING id, loan_id, user_id, amount, payment_date", [loanId, userId, repaymentAmount, key])).rows[0];
            await client.query("INSERT INTO audit_logs (actor_user_id, actor_role, event_type, target_type, target_id, metadata, ip_hash) VALUES ($1, 'borrower', 'repayment.create', 'repayment', $2, $3::jsonb, $4)", [userId, inserted.id, JSON.stringify({ loanId, idempotent: false }), auditIpHash(req)]);
            return { ok: true, idempotent: false, repayment: inserted, remainingBalance: remaining.minus(repaymentAmount).toString() };
        });
    } };
    if (!sqliteDb) throw new Error("A SQLite database or PostgreSQL database is required.");
    return { record({ loanId, userId, amount, req = null }) {
        const repaymentAmount = decimalString(String(amount), { positive: true, allowZero: false });
        return sqliteDb.transaction(() => {
            const loan = sqliteDb.prepare("SELECT * FROM loans WHERE id = ? AND user_id = ?").get(loanId, userId); if (!loan) return { ok: false, reason: "not_found" }; if (loan.status !== "Approved") return { ok: false, reason: "not_approved", loan }; if (!repaymentAmount) return { ok: false, reason: "invalid_amount" };
            const paid = sqliteDb.prepare("SELECT COALESCE(SUM(CAST(amount AS NUMERIC)), 0) AS total_paid FROM repayments WHERE loan_id = ? AND user_id = ?").get(loanId, userId).total_paid; const remaining = new Decimal(String(loan.total_repayment)).minus(String(paid)); if (new Decimal(repaymentAmount).gt(remaining)) return { ok: false, reason: "overpayment", remainingBalance: remaining.toString() };
            const inserted = sqliteDb.prepare("INSERT INTO repayments (loan_id, user_id, amount) VALUES (?, ?, ?)").run(loanId, userId, repaymentAmount); sqliteDb.prepare("INSERT INTO audit_logs (actor_user_id, actor_role, event_type, target_type, target_id, metadata, ip_hash) VALUES (?, 'borrower', 'repayment.create', 'repayment', ?, ?, ?)").run(userId, inserted.lastInsertRowid, JSON.stringify({ loanId, idempotent: false }), auditIpHash(req)); return { ok: true, idempotent: false, repayment: { id: inserted.lastInsertRowid }, remainingBalance: remaining.minus(repaymentAmount).toString() };
        })();
    } };
}
module.exports = { createRepaymentRepository, normalizeIdempotencyKey };
