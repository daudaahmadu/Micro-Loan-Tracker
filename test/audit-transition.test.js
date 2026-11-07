const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const http = require("node:http");
const { once } = require("node:events");
const bcrypt = require("bcryptjs");

const temporaryDirectory = fs.mkdtempSync(
    path.join(os.tmpdir(), "micro-loan-tracker-audit-transition-")
);
process.env.DATABASE_PATH = path.join(temporaryDirectory, "test.sqlite");
process.env.SESSION_SECRET = "test-only-audit-transition-secret-long-enough";
process.env.NODE_ENV = "test";
process.env.REDIS_URL ||= "redis://127.0.0.1:6380/15";
process.env.REDIS_KEY_PREFIX ||= `mlt:test:audit-transition:${process.pid}:`;

const { app, db, redisClient, redisReady } = require("../server");

const adminEmail = "audit-admin@example.test";
const adminPassword = "Audit-Admin-Password-123!";
const borrowerEmail = "audit-borrower@example.test";
const borrowerPassword = "Audit-Borrower-Password-123!";

let server;
let baseUrl;
let adminId;
let borrowerId;

function formBody(values) {
    return new URLSearchParams(values).toString();
}

async function request(pathname, options = {}) {
    const response = await fetch(`${baseUrl}${pathname}`, {
        redirect: "manual",
        ...options,
        headers: {
            ...(options.body ? { "content-type": "application/x-www-form-urlencoded" } : {}),
            ...(options.headers || {})
        }
    });
    return { response, text: await response.text() };
}

function cookieFrom(response) {
    return response.headers.get("set-cookie")?.split(";", 1)[0];
}

function tokenFrom(text) {
    const match = text.match(/name="_csrf" value="([a-f0-9]{64})"/);
    assert.ok(match, "expected a CSRF token");
    return match[1];
}

async function login(email, password) {
    const page = await request("/signin");
    const cookie = cookieFrom(page.response);
    const result = await request("/signin", {
        method: "POST",
        headers: { cookie },
        body: formBody({ email, password, _csrf: tokenFrom(page.text) })
    });
    assert.equal(result.response.status, 302);
    return cookieFrom(result.response);
}

async function actionToken(cookie) {
    const page = await request("/admin-dashboard", { headers: { cookie } });
    assert.equal(page.response.status, 200);
    return tokenFrom(page.text);
}

function createLoan(status = "Pending") {
    const result = db.prepare(`
        INSERT INTO loans (
            user_id, amount, interest_rate, interest_amount, total_repayment, purpose, status
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(borrowerId, 1000, 10, 100, 1100, "Audit transition test", status);
    return Number(result.lastInsertRowid);
}

function auditRows(eventType) {
    return db.prepare(
        "SELECT * FROM audit_logs WHERE event_type = ? ORDER BY id"
    ).all(eventType);
}

test.before(async () => {
    await redisReady;
    adminId = Number(db.prepare(
        "INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)"
    ).run(
        "Audit Administrator",
        adminEmail,
        bcrypt.hashSync(adminPassword, 10),
        "admin"
    ).lastInsertRowid);
    borrowerId = Number(db.prepare(
        "INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)"
    ).run(
        "Audit Borrower",
        borrowerEmail,
        bcrypt.hashSync(borrowerPassword, 10),
        "borrower"
    ).lastInsertRowid);
    server = http.createServer(app);
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    baseUrl = `http://127.0.0.1:${server.address().port}`;
});

test.after(async () => {
    db.close();
    server.close();
    await once(server, "close");
    await redisClient.quit();
    fs.rmSync(temporaryDirectory, { recursive: true, force: true });
});

test("records administrator authentication events without sensitive credentials", async () => {
    const adminCookie = await login(adminEmail, adminPassword);
    const success = auditRows("admin.signin.success");
    assert.equal(success.length, 1);
    assert.equal(success[0].actor_user_id, adminId);
    assert.equal(success[0].actor_role, "admin");
    assert.equal(success[0].metadata, null);
    assert.ok(success[0].ip_hash);

    const failedPage = await request("/signin");
    const failedCookie = cookieFrom(failedPage.response);
    const failed = await request("/signin", {
        method: "POST",
        headers: { cookie: failedCookie },
        body: formBody({
            email: adminEmail,
            password: "Wrong-Admin-Password-123!",
            _csrf: tokenFrom(failedPage.text)
        })
    });
    assert.equal(failed.response.status, 200);
    assert.equal(auditRows("admin.signin.failure").length, 1);

    const token = await actionToken(adminCookie);
    const logout = await request("/logout", {
        method: "POST",
        headers: { cookie: adminCookie },
        body: formBody({ _csrf: token })
    });
    assert.equal(logout.response.status, 302);
    assert.equal(auditRows("admin.logout").length, 1);
    const serialized = JSON.stringify(db.prepare("SELECT * FROM audit_logs").all());
    assert.equal(serialized.includes(adminPassword), false);
    assert.equal(serialized.includes("Wrong-Admin-Password-123!"), false);
});

test("enforces one-way pending loan transitions and records one audit event", async () => {
    const loanId = createLoan("Pending");
    const adminCookie = await login(adminEmail, adminPassword);
    const token = await actionToken(adminCookie);

    const approved = await request(`/admin/approve-loan/${loanId}`, {
        method: "POST",
        headers: { cookie: adminCookie },
        body: formBody({ _csrf: token })
    });
    assert.equal(approved.response.status, 302);
    assert.equal(db.prepare("SELECT status FROM loans WHERE id = ?").get(loanId).status, "Approved");
    assert.equal(auditRows("admin.loan.approve").filter(row => row.target_id === loanId).length, 1);

    const repeated = await request(`/admin/reject-loan/${loanId}`, {
        method: "POST",
        headers: { cookie: adminCookie },
        body: formBody({ _csrf: token })
    });
    assert.equal(repeated.response.status, 409);
    assert.equal(db.prepare("SELECT status FROM loans WHERE id = ?").get(loanId).status, "Approved");
    assert.equal(auditRows("admin.loan.reject").filter(row => row.target_id === loanId).length, 0);

    const rejectedLoanId = createLoan("Rejected");
    const rejectApproved = await request(`/admin/approve-loan/${rejectedLoanId}`, {
        method: "POST",
        headers: { cookie: adminCookie },
        body: formBody({ _csrf: token })
    });
    assert.equal(rejectApproved.response.status, 409);
    assert.equal(auditRows("admin.loan.approve").filter(row => row.target_id === rejectedLoanId).length, 0);
});

test("allows only one concurrent transition and blocks borrowers", async () => {
    const loanId = createLoan("Pending");
    const adminCookie = await login(adminEmail, adminPassword);
    const token = await actionToken(adminCookie);
    const results = await Promise.all([
        request(`/admin/approve-loan/${loanId}`, {
            method: "POST",
            headers: { cookie: adminCookie },
            body: formBody({ _csrf: token })
        }),
        request(`/admin/reject-loan/${loanId}`, {
            method: "POST",
            headers: { cookie: adminCookie },
            body: formBody({ _csrf: token })
        })
    ]);
    assert.deepEqual(results.map(result => result.response.status).sort(), [302, 409]);
    const status = db.prepare("SELECT status FROM loans WHERE id = ?").get(loanId).status;
    assert.ok(["Approved", "Rejected"].includes(status));
    const transitions = db.prepare(`
        SELECT COUNT(*) AS count
        FROM audit_logs
        WHERE target_type = 'loan' AND target_id = ?
    `).get(loanId).count;
    assert.equal(transitions, 1);

    const borrowerCookie = await login(borrowerEmail, borrowerPassword);
    const borrowerTokenPage = await request("/dashboard", {
        headers: { cookie: borrowerCookie }
    });
    const borrowerToken = tokenFrom(borrowerTokenPage.text);
    const unauthorized = await request(`/admin/approve-loan/${loanId}`, {
        method: "POST",
        headers: { cookie: borrowerCookie },
        body: formBody({ _csrf: borrowerToken })
    });
    assert.equal(unauthorized.response.status, 403);
    assert.equal(db.prepare("SELECT status FROM loans WHERE id = ?").get(loanId).status, status);
    assert.equal(auditRows("admin.authorization.denied").length, 1);
});

test("rolls back a loan transition when its audit insert fails", async () => {
    const loanId = createLoan("Pending");
    db.exec(`
        CREATE TRIGGER fail_reject_audit
        BEFORE INSERT ON audit_logs
        WHEN NEW.event_type = 'admin.loan.reject'
        BEGIN
            SELECT RAISE(ABORT, 'forced audit failure');
        END
    `);

    const adminCookie = await login(adminEmail, adminPassword);
    const token = await actionToken(adminCookie);
    const result = await request(`/admin/reject-loan/${loanId}`, {
        method: "POST",
        headers: { cookie: adminCookie },
        body: formBody({ _csrf: token })
    });

    assert.equal(result.response.status, 500);
    assert.equal(db.prepare("SELECT status FROM loans WHERE id = ?").get(loanId).status, "Pending");
    assert.equal(auditRows("admin.loan.reject").filter(row => row.target_id === loanId).length, 0);
    db.exec("DROP TRIGGER fail_reject_audit");
});
