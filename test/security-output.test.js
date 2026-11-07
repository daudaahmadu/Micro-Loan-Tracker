const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const http = require("node:http");
const { once } = require("node:events");
const bcrypt = require("bcryptjs");

const temporaryDirectory = fs.mkdtempSync(
    path.join(os.tmpdir(), "micro-loan-tracker-test-")
);
process.env.DATABASE_PATH = path.join(temporaryDirectory, "test.sqlite");
process.env.SESSION_SECRET = "test-only-session-secret-which-is-long-enough";
process.env.REDIS_URL ||= "redis://127.0.0.1:6380/15";
process.env.REDIS_KEY_PREFIX ||= `mlt:test:xss:${process.pid}:`;

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

    return {
        response,
        text: await response.text()
    };
}

function cookieFrom(response) {
    return response.headers.get("set-cookie")?.split(";", 1)[0];
}

function csrfTokenFrom(text) {
    const match = text.match(/name="_csrf" value="([a-f0-9]{64})"/);
    assert.ok(match, "expected a CSRF token in the form");
    return match[1];
}

async function signIn(email, password, expectedStatus = 302) {
    const result = await request("/signin", {
        method: "GET"
    });
    const cookie = cookieFrom(result.response);
    const token = csrfTokenFrom(result.text);

    const login = await request("/signin", {
        method: "POST",
        headers: { cookie },
        body: formBody({ email, password, _csrf: token })
    });
    assert.equal(login.response.status, expectedStatus);
    if (expectedStatus !== 302) {
        return null;
    }
    const authenticatedCookie = cookieFrom(login.response);
    assert.ok(authenticatedCookie);
    return authenticatedCookie;
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

test("escapes malicious borrower name and loan purpose in borrower pages", async () => {
    const email = `xss-${Date.now()}@example.test`;
    const name = '<img src=x onerror="alert(1)">';
    const purpose = '<script>alert("stored-xss")</script><b>unsafe</b>';

    const signupPage = await request("/signup");
    const signupCookie = cookieFrom(signupPage.response);
    const signupToken = csrfTokenFrom(signupPage.text);
    const signup = await request("/signup", {
        method: "POST",
        headers: { cookie: signupCookie },
        body: formBody({
            name,
            email,
            password: "Example-Password-123!",
            confirmPassword: "Example-Password-123!",
            _csrf: signupToken
        })
    });
    assert.equal(signup.response.status, 200);
    assert.match(signup.text, /Account created successfully/);

    const cookie = await signIn(email, "Example-Password-123!");
    const loanForm = await request("/request-loan", { headers: { cookie } });
    const loanToken = csrfTokenFrom(loanForm.text);
    const loan = await request("/request-loan", {
        method: "POST",
        headers: { cookie },
        body: formBody({ amount: "1000", interestRate: "5", purpose, _csrf: loanToken })
    });
    assert.equal(loan.response.status, 200);
    assert.match(loan.text, /Loan Request Submitted Successfully/);

    const dashboard = await request("/dashboard", { headers: { cookie } });
    assert.equal(dashboard.response.status, 200);
    assert.match(dashboard.text, /&lt;script&gt;alert\(&quot;stored-xss&quot;\)&lt;\/script&gt;/);
    assert.doesNotMatch(dashboard.text, /<script>alert\("stored-xss"\)<\/script>/);

    const myLoans = await request("/my-loans", { headers: { cookie } });
    assert.equal(myLoans.response.status, 200);
    assert.match(myLoans.text, /&lt;script&gt;alert\(&quot;stored-xss&quot;\)&lt;\/script&gt;/);
    assert.doesNotMatch(myLoans.text, /<script>alert\("stored-xss"\)<\/script>/);

    const repayments = await request("/repayments", { headers: { cookie } });
    assert.equal(repayments.response.status, 200);
    assert.doesNotMatch(repayments.text, /<script>alert\("stored-xss"\)<\/script>/);
});

test("escapes malicious borrower name, email, and event-handler HTML for administrators", async () => {
    const adminEmail = `admin-${Date.now()}@example.test`;
    const maliciousEmail = '<img src=x onerror="alert(3)">';
    const adminPassword = "Admin-Password-123!";
    const maliciousName = '<svg onload="alert(1)">';
    const maliciousPurpose = '<a href="javascript:alert(2)">click</a>';

    db.prepare("INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)").run(
        "Test Admin",
        adminEmail,
        bcrypt.hashSync(adminPassword, 10),
        "admin"
    );
    db.prepare("INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)").run(
        maliciousName,
        maliciousEmail,
        "not-used-by-this-test",
        "borrower"
    );

    const borrower = db.prepare("SELECT id FROM users WHERE email = ?").get(maliciousEmail);
    db.prepare(`
        INSERT INTO loans (user_id, amount, interest_rate, interest_amount, total_repayment, purpose)
        VALUES (?, ?, ?, ?, ?, ?)
    `).run(borrower.id, 1000, 5, 50, 1050, maliciousPurpose);

    const cookie = await signIn(adminEmail, adminPassword);
    const adminDashboard = await request("/admin-dashboard", { headers: { cookie } });
    assert.equal(adminDashboard.response.status, 200);
    assert.match(adminDashboard.text, /&lt;svg onload=&quot;alert\(1\)&quot;&gt;/);
    assert.match(adminDashboard.text, /&lt;img src=x onerror=&quot;alert\(3\)&quot;&gt;/);
    assert.match(adminDashboard.text, /&lt;a href=&quot;javascript:alert\(2\)&quot;&gt;click&lt;\/a&gt;/);
    assert.doesNotMatch(adminDashboard.text, /<svg onload="alert\(1\)">/);
    assert.doesNotMatch(adminDashboard.text, /<img src=x onerror="alert\(3\)">/);
    assert.doesNotMatch(adminDashboard.text, /<a href="javascript:alert\(2\)">click<\/a>/);
});

test("escapes malicious repayment status and payment date while preserving repayment behavior", async () => {
    const email = `repayment-${Date.now()}@example.test`;
    const password = "Repayment-Password-123!";
    const maliciousStatus = '<img src=x onerror="alert(4)">';
    const maliciousPaymentDate = '<svg onload="alert(5)">';

    const userResult = db.prepare(
        "INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)"
    ).run("Repayment User", email, bcrypt.hashSync(password, 10), "borrower");
    const userId = Number(userResult.lastInsertRowid);

    const loanResult = db.prepare(`
        INSERT INTO loans (user_id, amount, interest_rate, interest_amount, total_repayment, purpose, status)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(userId, 100, 5, 5, 105, "Working capital", maliciousStatus);
    const loanId = Number(loanResult.lastInsertRowid);

    const cookie = await signIn(email, password);
    const repaymentForm = await request("/repayments", { headers: { cookie } });
    const repaymentToken = csrfTokenFrom(repaymentForm.text);
    const blockedResponse = await request("/repayments", {
        method: "POST",
        headers: { cookie },
        body: formBody({ loanId, amount: "10", _csrf: repaymentToken })
    });
    assert.equal(blockedResponse.response.status, 200);
    assert.match(blockedResponse.text, /&lt;img src=x onerror=&quot;alert\(4\)&quot;&gt;/);
    assert.doesNotMatch(blockedResponse.text, /<img src=x onerror="alert\(4\)">/);

    db.prepare("UPDATE loans SET status = 'Approved' WHERE id = ?").run(loanId);
    const successfulResponse = await request("/repayments", {
        method: "POST",
        headers: { cookie },
        body: formBody({ loanId, amount: "10", _csrf: repaymentToken })
    });
    assert.equal(successfulResponse.response.status, 200);
    assert.match(successfulResponse.text, /Repayment Recorded Successfully/);
    assert.doesNotMatch(successfulResponse.text, /<script|onerror=|onload=/i);

    db.prepare(
        "INSERT INTO repayments (loan_id, user_id, amount, payment_date) VALUES (?, ?, ?, ?)"
    ).run(loanId, userId, 1, maliciousPaymentDate);
    const repaymentHistory = await request("/repayments", { headers: { cookie } });
    assert.equal(repaymentHistory.response.status, 200);
    assert.match(repaymentHistory.text, /&lt;svg onload=&quot;alert\(5\)&quot;&gt;/);
    assert.doesNotMatch(repaymentHistory.text, /<svg onload="alert\(5\)">/);
});
