const crypto = require("node:crypto");

function asNumber(value) {
    const number = Number(value);
    return Number.isFinite(number) ? number : 0;
}

function normalizeLoan(row) {
    if (!row) return row;
    return {
        ...row,
        id: asNumber(row.id),
        user_id: asNumber(row.user_id),
        amount: asNumber(row.amount),
        interest_rate: asNumber(row.interest_rate),
        interest_amount: asNumber(row.interest_amount),
        total_repayment: asNumber(row.total_repayment)
    };
}

function normalizeRepayment(row) {
    if (!row) return row;
    return { ...row, id: asNumber(row.id), loan_id: asNumber(row.loan_id), user_id: asNumber(row.user_id), amount: asNumber(row.amount), loan_amount: asNumber(row.loan_amount), total_repayment: asNumber(row.total_repayment) };
}

function createDataRepository({ sqliteDb, postgres, sessionSecret }) {
    const isPostgres = Boolean(postgres);
    const ipHash = req => req?.ip ? crypto.createHash("sha256").update(`${sessionSecret}:${req.ip}`).digest("hex") : null;
    const query = (text, values) => postgres.query(text, values);

    return {
        isPostgres,
        async findUserByEmail(email) {
            if (isPostgres) return (await query("SELECT * FROM users WHERE lower(email) = lower($1)", [email])).rows[0] || null;
            return sqliteDb.prepare("SELECT * FROM users WHERE lower(email) = lower(?)").get(email) || null;
        },
        async createUser({ name, email, password }) {
            if (isPostgres) {
                try { return (await query("INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING id", [name, email, password])).rows[0]; }
                catch (error) { if (error.code === "23505") error.code = "ACCOUNT_EXISTS"; throw error; }
            }
            try { return sqliteDb.prepare("INSERT INTO users (name, email, password) VALUES (?, ?, ?)").run(name, email, password); }
            catch (error) { if (error.code === "SQLITE_CONSTRAINT_UNIQUE") error.code = "ACCOUNT_EXISTS"; throw error; }
        },
        async listUserLoans(userId) {
            const rows = isPostgres
                ? (await query("SELECT * FROM loans WHERE user_id = $1 ORDER BY created_at DESC", [userId])).rows
                : sqliteDb.prepare("SELECT * FROM loans WHERE user_id = ? ORDER BY created_at DESC").all(userId);
            return rows.map(normalizeLoan);
        },
        async repaymentSummary(userId = null) {
            const rows = isPostgres
                ? (await query(userId === null ? "SELECT loan_id, COALESCE(SUM(amount), 0) AS total_repaid FROM repayments GROUP BY loan_id" : "SELECT loan_id, COALESCE(SUM(amount), 0) AS total_repaid FROM repayments WHERE user_id = $1 GROUP BY loan_id", userId === null ? [] : [userId])).rows
                : (userId === null ? sqliteDb.prepare("SELECT loan_id, COALESCE(SUM(amount), 0) AS total_repaid FROM repayments GROUP BY loan_id").all() : sqliteDb.prepare("SELECT loan_id, COALESCE(SUM(amount), 0) AS total_repaid FROM repayments WHERE user_id = ? GROUP BY loan_id").all(userId));
            return rows.map(row => ({ ...row, loan_id: asNumber(row.loan_id), total_repaid: asNumber(row.total_repaid) }));
        },
        async adminLoans() {
            const rows = isPostgres
                ? (await query("SELECT loans.*, users.name AS borrower_name, users.email AS borrower_email FROM loans JOIN users ON loans.user_id = users.id ORDER BY loans.created_at DESC")).rows
                : sqliteDb.prepare("SELECT loans.*, users.name AS borrower_name, users.email AS borrower_email FROM loans JOIN users ON loans.user_id = users.id ORDER BY loans.created_at DESC").all();
            return rows.map(normalizeLoan);
        },
        async totalRepaid() {
            const row = isPostgres ? (await query("SELECT COALESCE(SUM(amount), 0) AS total_repaid FROM repayments")).rows[0] : sqliteDb.prepare("SELECT COALESCE(SUM(amount), 0) AS total_repaid FROM repayments").get();
            return asNumber(row.total_repaid);
        },
        async repaymentRecords(userId) {
            const rows = isPostgres
                ? (await query("SELECT repayments.*, loans.amount AS loan_amount, loans.total_repayment FROM repayments JOIN loans ON repayments.loan_id = loans.id WHERE repayments.user_id = $1 ORDER BY repayments.payment_date DESC", [userId])).rows
                : sqliteDb.prepare("SELECT repayments.*, loans.amount AS loan_amount, loans.total_repayment FROM repayments JOIN loans ON repayments.loan_id = loans.id WHERE repayments.user_id = ? ORDER BY repayments.payment_date DESC").all(userId);
            return rows.map(normalizeRepayment);
        },
        async createLoan({ userId, amount, rate, interestAmount, totalRepayment, purpose }) {
            if (isPostgres) return (await query("INSERT INTO loans (user_id, amount, interest_rate, interest_amount, total_repayment, purpose) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id", [userId, amount, rate, interestAmount, totalRepayment, purpose])).rows[0];
            return sqliteDb.prepare("INSERT INTO loans (user_id, amount, interest_rate, interest_amount, total_repayment, purpose) VALUES (?, ?, ?, ?, ?, ?)").run(userId, amount, rate, interestAmount, totalRepayment, purpose);
        },
        async transitionLoanStatus({ loanId, nextStatus, actorUserId, req, eventType }) {
            if (isPostgres) return postgres.transaction(async client => {
                const result = await client.query("UPDATE loans SET status = $1 WHERE id = $2 AND status = 'Pending'", [nextStatus, loanId]);
                if (result.rowCount !== 1) return false;
                await client.query("INSERT INTO audit_logs (actor_user_id, actor_role, event_type, target_type, target_id, ip_hash) VALUES ($1, 'admin', $2, 'loan', $3, $4)", [actorUserId, eventType, loanId, ipHash(req)]);
                return true;
            });
            return sqliteDb.transaction(() => {
                const result = sqliteDb.prepare("UPDATE loans SET status = ? WHERE id = ? AND status = 'Pending'").run(nextStatus, loanId);
                if (result.changes !== 1) return false;
                const serialized = null;
                sqliteDb.prepare("INSERT INTO audit_logs (actor_user_id, actor_role, event_type, target_type, target_id, metadata, ip_hash) VALUES (?, ?, ?, ?, ?, ?, ?)").run(
                    actorUserId,
                    "admin",
                    eventType,
                    "loan",
                    loanId,
                    serialized,
                    ipHash(req)
                );
                return true;
            })();
        },
        async writeAuditLog({ actorUserId = null, actorRole = null, eventType, targetType = null, targetId = null, metadata = null, req = null }) {
            const serialized = metadata === null ? null : JSON.stringify(metadata);
            if (isPostgres) return query("INSERT INTO audit_logs (actor_user_id, actor_role, event_type, target_type, target_id, metadata, ip_hash) VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7)", [actorUserId, actorRole, eventType, targetType, targetId, serialized, ipHash(req)]);
            return sqliteDb.prepare("INSERT INTO audit_logs (actor_user_id, actor_role, event_type, target_type, target_id, metadata, ip_hash) VALUES (?, ?, ?, ?, ?, ?, ?)").run(actorUserId, actorRole, eventType, targetType, targetId, serialized, ipHash(req));
        }
    };
}

module.exports = { createDataRepository, asNumber };
