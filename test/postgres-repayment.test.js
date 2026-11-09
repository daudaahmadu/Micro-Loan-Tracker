const test = require("node:test");
const assert = require("node:assert/strict");
const { createPostgresDatabase } = require("../lib/postgres");
const { createRepaymentRepository } = require("../lib/repayment-repository");

const database = createPostgresDatabase();

test.after(async () => {
    if (database) await database.close();
});

test("PostgreSQL schema and repayment locking/idempotency fixture", { skip: !process.env.DATABASE_URL }, async () => {
    await database.initializeSchema();
    const suffix = `${Date.now()}-${process.pid}`;
    const user = await database.query(
        "INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING id",
        ["Synthetic Borrower", `borrower-${suffix}@example.test`, "test-hash"]
    );
    const loan = await database.query(
        `INSERT INTO loans (user_id, amount, interest_rate, interest_amount, total_repayment, purpose, status)
         VALUES ($1, 100, 5, 5, 105, 'fixture', 'Approved') RETURNING id`,
        [user.rows[0].id]
    );
    const repository = createRepaymentRepository({ postgres: database });
    const first = await repository.record({ loanId: loan.rows[0].id, userId: user.rows[0].id, amount: 10, idempotencyKey: `fixture-${suffix}` });
    const repeated = await repository.record({ loanId: loan.rows[0].id, userId: user.rows[0].id, amount: 10, idempotencyKey: `fixture-${suffix}` });
    assert.equal(first.ok, true);
    assert.equal(repeated.idempotent, true);
    assert.equal((await database.query("SELECT COUNT(*)::int AS count FROM repayments WHERE loan_id = $1", [loan.rows[0].id])).rows[0].count, 1);
    await database.query("DELETE FROM repayments WHERE loan_id = $1", [loan.rows[0].id]);
    await database.query("DELETE FROM loans WHERE id = $1", [loan.rows[0].id]);
    await database.query("DELETE FROM users WHERE id = $1", [user.rows[0].id]);
});

test("serializes concurrent repayments and never exceeds the outstanding balance", { skip: !process.env.DATABASE_URL }, async () => {
    const suffix = `${Date.now()}-${process.pid}-concurrent`;
    const user = await database.query(
        "INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING id",
        ["Concurrent Borrower", `concurrent-${suffix}@example.test`, "test-hash"]
    );
    const loan = await database.query(
        `INSERT INTO loans (user_id, amount, interest_rate, interest_amount, total_repayment, purpose, status)
         VALUES ($1, 100, 5, 5, 100, 'concurrent fixture', 'Approved') RETURNING id`,
        [user.rows[0].id]
    );
    const repository = createRepaymentRepository({ postgres: database });
    const results = await Promise.all([
        repository.record({ loanId: loan.rows[0].id, userId: user.rows[0].id, amount: 60, idempotencyKey: `concurrent-a-${suffix}` }),
        repository.record({ loanId: loan.rows[0].id, userId: user.rows[0].id, amount: 60, idempotencyKey: `concurrent-b-${suffix}` })
    ]);

    assert.equal(results.filter(result => result.ok).length, 1);
    assert.equal(results.filter(result => result.reason === "overpayment").length, 1);
    const total = await database.query(
        "SELECT COALESCE(SUM(amount), 0) AS total FROM repayments WHERE loan_id = $1",
        [loan.rows[0].id]
    );
    assert.equal(Number(total.rows[0].total), 60);

    await database.query("DELETE FROM repayments WHERE loan_id = $1", [loan.rows[0].id]);
    await database.query("DELETE FROM loans WHERE id = $1", [loan.rows[0].id]);
    await database.query("DELETE FROM users WHERE id = $1", [user.rows[0].id]);
});

test("serializes concurrent duplicate idempotency keys to one repayment", { skip: !process.env.DATABASE_URL }, async () => {
    const suffix = `${Date.now()}-${process.pid}-idempotent`;
    const user = await database.query(
        "INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING id",
        ["Idempotent Borrower", `idempotent-${suffix}@example.test`, "test-hash"]
    );
    const loan = await database.query(
        `INSERT INTO loans (user_id, amount, interest_rate, interest_amount, total_repayment, purpose, status)
         VALUES ($1, 100, 5, 5, 100, 'idempotency fixture', 'Approved') RETURNING id`,
        [user.rows[0].id]
    );
    const repository = createRepaymentRepository({ postgres: database });
    const key = `same-key-${suffix}`;
    const results = await Promise.all([
        repository.record({ loanId: loan.rows[0].id, userId: user.rows[0].id, amount: 25, idempotencyKey: key }),
        repository.record({ loanId: loan.rows[0].id, userId: user.rows[0].id, amount: 25, idempotencyKey: key })
    ]);

    assert.equal(results.filter(result => result.ok).length, 2);
    assert.equal(results.filter(result => result.idempotent === true).length, 1);
    assert.equal((await database.query("SELECT COUNT(*)::int AS count FROM repayments WHERE loan_id = $1", [loan.rows[0].id])).rows[0].count, 1);

    await database.query("DELETE FROM repayments WHERE loan_id = $1", [loan.rows[0].id]);
    await database.query("DELETE FROM loans WHERE id = $1", [loan.rows[0].id]);
    await database.query("DELETE FROM users WHERE id = $1", [user.rows[0].id]);
});
