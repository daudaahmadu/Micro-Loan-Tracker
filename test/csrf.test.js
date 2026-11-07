const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const http = require("node:http");
const { once } = require("node:events");
const bcrypt = require("bcryptjs");

const temporaryDirectory = fs.mkdtempSync(
    path.join(os.tmpdir(), "micro-loan-tracker-csrf-")
);
process.env.DATABASE_PATH = path.join(temporaryDirectory, "test.sqlite");
process.env.SESSION_SECRET = "test-only-csrf-session-secret-which-is-long-enough";
process.env.REDIS_URL ||= "redis://127.0.0.1:6380/15";
process.env.REDIS_KEY_PREFIX ||= `mlt:test:csrf:${process.pid}:`;

const { app, db, redisClient, redisReady } = require("../server");

let server;
let baseUrl;

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
    assert.ok(match, "expected a 32-byte hexadecimal CSRF token");
    return match[1];
}

async function pageToken(pathname, cookie) {
    const result = await request(pathname, {
        headers: cookie ? { cookie } : undefined
    });
    const nextCookie = cookieFrom(result.response) || cookie;
    return { cookie: nextCookie, token: tokenFrom(result.text), text: result.text };
}

async function login(email, password) {
    const form = await pageToken("/signin");
    const result = await request("/signin", {
        method: "POST",
        headers: { cookie: form.cookie },
        body: formBody({ email, password, _csrf: form.token })
    });
    assert.equal(result.response.status, 302);
    const cookie = cookieFrom(result.response);
    assert.ok(cookie, "successful login should issue a session cookie");
    return { cookie, oldCookie: form.cookie, preLoginToken: form.token };
}

function createUser(name, email, password, role = "borrower") {
    const result = db.prepare(
        "INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)"
    ).run(name, email, bcrypt.hashSync(password, 10), role);
    return Number(result.lastInsertRowid);
}

function createLoan(userId, status = "Pending") {
    const result = db.prepare(`
        INSERT INTO loans (user_id, amount, interest_rate, interest_amount, total_repayment, purpose, status)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(userId, 100, 5, 5, 105, "Working capital", status);
    return Number(result.lastInsertRowid);
}

test.before(async () => {
    await redisReady;
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

test("all protected forms contain session-bound tokens and valid borrower/admin workflows work", async () => {
    const borrowerEmail = `borrower-${Date.now()}@example.test`;
    const adminEmail = `admin-${Date.now()}@example.test`;
    const borrowerPassword = "Borrower-Password-123!";
    const adminPassword = "Admin-Password-123!";
    const borrowerId = createUser("Borrower", borrowerEmail, borrowerPassword);
    createUser("Administrator", adminEmail, adminPassword, "admin");

    for (const pathname of ["/signup", "/signin"]) {
        const form = await pageToken(pathname);
        assert.equal(form.token.length, 64);
        assert.match(form.text, /<input type="hidden" name="_csrf" value="[a-f0-9]{64}">/);
    }

    const newSignup = await pageToken("/signup");
    const registered = await request("/signup", {
        method: "POST",
        headers: { cookie: newSignup.cookie },
        body: formBody({
            name: "Registered User",
            email: `registered-${Date.now()}@example.test`,
            password: "Registered-Password-123!",
            confirmPassword: "Registered-Password-123!",
            _csrf: newSignup.token
        })
    });
    assert.equal(registered.response.status, 200);
    assert.match(registered.text, /Account created successfully/);

    const borrowerSession = await login(borrowerEmail, borrowerPassword);
    const borrowerPage = await pageToken("/dashboard", borrowerSession.cookie);
    assert.notEqual(borrowerPage.token, borrowerSession.preLoginToken);
    const oldSessionDashboard = await request("/dashboard", {
        headers: { cookie: borrowerSession.oldCookie }
    });
    assert.equal(oldSessionDashboard.response.status, 302);

    const loanRequest = await request("/request-loan", {
        method: "POST",
        headers: { cookie: borrowerSession.cookie },
        body: formBody({
            amount: "100",
            interestRate: "5",
            purpose: "Valid purpose",
            _csrf: borrowerPage.token
        })
    });
    assert.equal(loanRequest.response.status, 200);
    assert.equal(db.prepare("SELECT COUNT(*) AS count FROM loans WHERE user_id = ?").get(borrowerId).count, 1);

    const loanId = createLoan(borrowerId, "Approved");
    const repaymentPage = await pageToken("/repayments", borrowerSession.cookie);
    const repayment = await request("/repayments", {
        method: "POST",
        headers: { cookie: borrowerSession.cookie },
        body: formBody({ loanId, amount: "10", _csrf: repaymentPage.token })
    });
    assert.equal(repayment.response.status, 200);
    assert.match(repayment.text, /Repayment Recorded Successfully/);

    const adminSession = await login(adminEmail, adminPassword);
    const pendingLoanToApprove = createLoan(borrowerId);
    const adminPage = await pageToken("/admin-dashboard", adminSession.cookie);
    assert.match(adminPage.text, /method="POST"/);
    assert.match(adminPage.text, new RegExp(`name="_csrf" value="${adminPage.token}"`));

    const approve = await request(`/admin/approve-loan/${pendingLoanToApprove}`, {
        method: "POST",
        headers: { cookie: adminSession.cookie },
        body: formBody({ _csrf: adminPage.token })
    });
    assert.equal(approve.response.status, 302);
    assert.equal(db.prepare("SELECT status FROM loans WHERE id = ?").get(pendingLoanToApprove).status, "Approved");

    const pendingLoanToReject = createLoan(borrowerId);
    const adminPageAgain = await pageToken("/admin-dashboard", adminSession.cookie);
    const reject = await request(`/admin/reject-loan/${pendingLoanToReject}`, {
        method: "POST",
        headers: { cookie: adminSession.cookie },
        body: formBody({ _csrf: adminPageAgain.token })
    });
    assert.equal(reject.response.status, 302);
    assert.equal(db.prepare("SELECT status FROM loans WHERE id = ?").get(pendingLoanToReject).status, "Rejected");

    const logoutPage = await pageToken("/dashboard", borrowerSession.cookie);
    const logout = await request("/logout", {
        method: "POST",
        headers: { cookie: borrowerSession.cookie },
        body: formBody({ _csrf: logoutPage.token })
    });
    assert.equal(logout.response.status, 302);
    assert.equal(logout.response.headers.get("location"), "/signin");
});

test("missing, invalid, cross-session, and query-string tokens are rejected", async () => {
    const borrowerEmail = `csrf-borrower-${Date.now()}@example.test`;
    const otherEmail = `csrf-other-${Date.now()}@example.test`;
    const password = "Borrower-Password-123!";
    const borrowerId = createUser("Borrower", borrowerEmail, password);
    createUser("Other Borrower", otherEmail, password);
    const loanId = createLoan(borrowerId, "Approved");
    const borrowerSession = await login(borrowerEmail, password);
    const otherSession = await login(otherEmail, password);
    const borrowerPage = await pageToken("/dashboard", borrowerSession.cookie);
    const otherPage = await pageToken("/dashboard", otherSession.cookie);

    const cases = [
        {
            name: "registration missing token",
            pathname: "/signup",
            body: {
                name: "Should Not Register",
                email: `blocked-${Date.now()}@example.test`,
                password: "Password-123!",
                confirmPassword: "Password-123!"
            },
            cookie: (await pageToken("/signup")).cookie
        },
        {
            name: "loan request missing token",
            pathname: "/request-loan",
            body: { amount: "100", interestRate: "5", purpose: "Should not save" }
        },
        {
            name: "repayment invalid token",
            pathname: "/repayments",
            body: { loanId, amount: "10", _csrf: "invalid-token" }
        },
        {
            name: "repayment cross-session token",
            pathname: "/repayments",
            body: { loanId, amount: "10", _csrf: otherPage.token }
        },
        {
            name: "loan request token supplied only in query string",
            pathname: `/request-loan?_csrf=${encodeURIComponent(borrowerPage.token)}`,
            body: { amount: "100", interestRate: "5", purpose: "Should not save" }
        },
        {
            name: "logout missing token",
            pathname: "/logout",
            body: {}
        }
    ];

    for (const item of cases) {
        const result = await request(item.pathname, {
            method: "POST",
            headers: { cookie: item.cookie || borrowerSession.cookie },
            body: formBody(item.body)
        });
        assert.equal(result.response.status, 403, item.name);
    }

    assert.equal(db.prepare("SELECT COUNT(*) AS count FROM repayments WHERE loan_id = ?").get(loanId).count, 0);
    assert.equal(db.prepare("SELECT COUNT(*) AS count FROM loans WHERE user_id = ?").get(borrowerId).count, 1);
});

test("GET requests cannot change administrator loan state or log out a session", async () => {
    const borrowerEmail = `get-borrower-${Date.now()}@example.test`;
    const adminEmail = `get-admin-${Date.now()}@example.test`;
    const password = "Password-123!";
    const borrowerId = createUser("Borrower", borrowerEmail, password);
    createUser("Administrator", adminEmail, password, "admin");
    const loanId = createLoan(borrowerId, "Pending");
    const adminSession = await login(adminEmail, password);
    const adminPage = await pageToken("/admin-dashboard", adminSession.cookie);

    const approveMissing = await request(`/admin/approve-loan/${loanId}`, {
        method: "POST",
        headers: { cookie: adminSession.cookie },
        body: ""
    });
    assert.equal(approveMissing.response.status, 403);
    const rejectInvalid = await request(`/admin/reject-loan/${loanId}`, {
        method: "POST",
        headers: { cookie: adminSession.cookie },
        body: formBody({ _csrf: "invalid-token" })
    });
    assert.equal(rejectInvalid.response.status, 403);
    assert.equal(db.prepare("SELECT status FROM loans WHERE id = ?").get(loanId).status, "Pending");

    const approveGet = await request(`/admin/approve-loan/${loanId}`, {
        headers: { cookie: adminSession.cookie }
    });
    const rejectGet = await request(`/admin/reject-loan/${loanId}`, {
        headers: { cookie: adminSession.cookie }
    });
    assert.equal(approveGet.response.status, 404);
    assert.equal(rejectGet.response.status, 404);
    assert.equal(db.prepare("SELECT status FROM loans WHERE id = ?").get(loanId).status, "Pending");

    const logoutGet = await request("/logout", { headers: { cookie: adminSession.cookie } });
    assert.equal(logoutGet.response.status, 404);

    const stillAuthenticated = await request("/admin-dashboard", {
        headers: { cookie: adminSession.cookie }
    });
    assert.equal(stillAuthenticated.response.status, 200);
    assert.ok(adminPage.token);
});

test("sign-in rejects missing and cross-session tokens before authenticating", async () => {
    const email = `signin-${Date.now()}@example.test`;
    const password = "Signin-Password-123!";
    createUser("Sign-in User", email, password);
    const first = await pageToken("/signin");
    const second = await pageToken("/signin");

    const missing = await request("/signin", {
        method: "POST",
        headers: { cookie: first.cookie },
        body: formBody({ email, password })
    });
    assert.equal(missing.response.status, 403);

    const crossSession = await request("/signin", {
        method: "POST",
        headers: { cookie: first.cookie },
        body: formBody({ email, password, _csrf: second.token })
    });
    assert.equal(crossSession.response.status, 403);
});
