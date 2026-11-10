const crypto = require("node:crypto");
const { canonicalDecimalString, add, subtract, nonNegative } = require("./decimal");

function asNumber(value) { const number = Number(value); return Number.isFinite(number) ? number : 0; }
function asMoney(value) { return canonicalDecimalString(String(value ?? "0")) || "0"; }
function normalizeLoan(row) {
    if (!row) return row;
    return { ...row, id: asNumber(row.id), user_id: asNumber(row.user_id), amount: asMoney(row.amount), interest_rate: asMoney(row.interest_rate), interest_amount: asMoney(row.interest_amount), total_repayment: asMoney(row.total_repayment) };
}
function normalizeRepayment(row) {
    if (!row) return row;
    return { ...row, id: asNumber(row.id), loan_id: asNumber(row.loan_id), user_id: asNumber(row.user_id), amount: asMoney(row.amount), loan_amount: asMoney(row.loan_amount), total_repayment: asMoney(row.total_repayment) };
}

function createDataRepository({ sqliteDb, postgres, sessionSecret }) {
    const isPostgres = Boolean(postgres);
    const ipHash = req => req?.ip ? crypto.createHash("sha256").update(`${sessionSecret}:${req.ip}`).digest("hex") : null;
    const query = (text, values) => postgres.query(text, values);
    const auditSql = `INSERT INTO audit_logs (actor_user_id, actor_role, event_type, target_type, target_id, metadata, ip_hash) VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7)`;
    const sqliteAudit = `INSERT INTO audit_logs (actor_user_id, actor_role, event_type, target_type, target_id, metadata, ip_hash) VALUES (?, ?, ?, ?, ?, ?, ?)`;
    return {
        isPostgres,
        async findUserByEmail(email) { return isPostgres ? (await query("SELECT * FROM users WHERE lower(email) = lower($1)", [email])).rows[0] || null : sqliteDb.prepare("SELECT * FROM users WHERE lower(email) = lower(?)").get(email) || null; },
        async createUser({ name, email, password }) {
            try {
                if (isPostgres) return (await query("INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING id", [name, email, password])).rows[0];
                return sqliteDb.prepare("INSERT INTO users (name, email, password) VALUES (?, ?, ?)").run(name, email, password);
            } catch (error) { if (["23505", "SQLITE_CONSTRAINT_UNIQUE"].includes(error.code)) error.code = "ACCOUNT_EXISTS"; throw error; }
        },
        async listUserLoans(userId) { const rows = isPostgres ? (await query("SELECT * FROM loans WHERE user_id = $1 ORDER BY created_at DESC", [userId])).rows : sqliteDb.prepare("SELECT * FROM loans WHERE user_id = ? ORDER BY created_at DESC").all(userId); return rows.map(normalizeLoan); },
        async repaymentSummary(userId = null) {
            const rows = isPostgres ? (await query(userId === null ? "SELECT loan_id, COALESCE(SUM(amount), 0) AS total_repaid FROM repayments GROUP BY loan_id" : "SELECT loan_id, COALESCE(SUM(amount), 0) AS total_repaid FROM repayments WHERE user_id = $1 GROUP BY loan_id", userId === null ? [] : [userId])).rows : (userId === null ? sqliteDb.prepare("SELECT loan_id, COALESCE(SUM(CAST(amount AS NUMERIC)), 0) AS total_repaid FROM repayments GROUP BY loan_id").all() : sqliteDb.prepare("SELECT loan_id, COALESCE(SUM(CAST(amount AS NUMERIC)), 0) AS total_repaid FROM repayments WHERE user_id = ? GROUP BY loan_id").all(userId));
            return rows.map(row => ({ ...row, loan_id: asNumber(row.loan_id), total_repaid: asMoney(row.total_repaid) }));
        },
        async adminLoans() { const rows = isPostgres ? (await query("SELECT loans.*, users.name AS borrower_name, users.email AS borrower_email FROM loans JOIN users ON loans.user_id = users.id ORDER BY loans.created_at DESC")).rows : sqliteDb.prepare("SELECT loans.*, users.name AS borrower_name, users.email AS borrower_email FROM loans JOIN users ON loans.user_id = users.id ORDER BY loans.created_at DESC").all(); return rows.map(normalizeLoan); },
        async totalRepaid() { const row = isPostgres ? (await query("SELECT COALESCE(SUM(amount), 0) AS total_repaid FROM repayments")).rows[0] : sqliteDb.prepare("SELECT COALESCE(SUM(CAST(amount AS NUMERIC)), 0) AS total_repaid FROM repayments").get(); return asMoney(row.total_repaid); },
        async repaymentRecords(userId) { const rows = isPostgres ? (await query("SELECT repayments.*, loans.amount AS loan_amount, loans.total_repayment FROM repayments JOIN loans ON repayments.loan_id = loans.id WHERE repayments.user_id = $1 ORDER BY repayments.payment_date DESC", [userId])).rows : sqliteDb.prepare("SELECT repayments.*, loans.amount AS loan_amount, loans.total_repayment FROM repayments JOIN loans ON repayments.loan_id = loans.id WHERE repayments.user_id = ? ORDER BY repayments.payment_date DESC").all(userId); return rows.map(normalizeRepayment); },
        async createLoan({ userId, amount, rate, interestAmount, totalRepayment, purpose, req = null }) {
            const metadata = JSON.stringify({ purpose });
            if (isPostgres) return postgres.transaction(async client => {
                const created = (await client.query("INSERT INTO loans (user_id, amount, interest_rate, interest_amount, total_repayment, purpose) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id", [userId, amount, rate, interestAmount, totalRepayment, purpose])).rows[0];
                await client.query(auditSql, [userId, "borrower", "loan.create", "loan", created.id, metadata, ipHash(req)]);
                return created;
            });
            return sqliteDb.transaction(() => { const created = sqliteDb.prepare("INSERT INTO loans (user_id, amount, interest_rate, interest_amount, total_repayment, purpose) VALUES (?, ?, ?, ?, ?, ?)").run(userId, amount, rate, interestAmount, totalRepayment, purpose); sqliteDb.prepare(sqliteAudit).run(userId, "borrower", "loan.create", "loan", created.lastInsertRowid, metadata, ipHash(req)); return created; })();
        },
        async transitionLoanStatus({ loanId, nextStatus, actorUserId, req, eventType }) {
            if (isPostgres) return postgres.transaction(async client => { const result = await client.query("UPDATE loans SET status = $1 WHERE id = $2 AND status = 'Pending'", [nextStatus, loanId]); if (result.rowCount !== 1) return false; await client.query(auditSql, [actorUserId, "admin", eventType, "loan", loanId, null, ipHash(req)]); return true; });
            return sqliteDb.transaction(() => { const result = sqliteDb.prepare("UPDATE loans SET status = ? WHERE id = ? AND status = 'Pending'").run(nextStatus, loanId); if (result.changes !== 1) return false; sqliteDb.prepare(sqliteAudit).run(actorUserId, "admin", eventType, "loan", loanId, null, ipHash(req)); return true; })();
        },
        async writeAuditLog({ actorUserId = null, actorRole = null, eventType, targetType = null, targetId = null, metadata = null, req = null }) {
            const serialized = metadata === null ? null : JSON.stringify(metadata);
            if (isPostgres) return query(auditSql, [actorUserId, actorRole, eventType, targetType, targetId, serialized, ipHash(req)]);
            return sqliteDb.prepare(sqliteAudit).run(actorUserId, actorRole, eventType, targetType, targetId, serialized, ipHash(req));
        }
    };
}
module.exports = { createDataRepository, asNumber, asMoney, add, subtract, nonNegative };
