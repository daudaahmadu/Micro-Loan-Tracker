const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const http = require("node:http");
const { once } = require("node:events");
const bcrypt = require("bcryptjs");

const temporaryDirectory = fs.mkdtempSync(
    path.join(os.tmpdir(), "micro-loan-tracker-validation-")
);
process.env.DATABASE_PATH = path.join(temporaryDirectory, "test.sqlite");
process.env.SESSION_SECRET = "test-only-validation-rate-limit-secret-long-enough";
process.env.NODE_ENV = "test";
process.env.REDIS_URL ||= "redis://127.0.0.1:6380/15";
process.env.REDIS_KEY_PREFIX ||= `mlt:test:validation:${process.pid}:`;

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
    assert.ok(match, "expected a CSRF token");
    return match[1];
}

async function pageToken(pathname, cookie) {
    const result = await request(pathname, {
        headers: cookie ? { cookie } : undefined
    });
    return {
        cookie: cookieFrom(result.response) || cookie,
        token: tokenFrom(result.text)
    };
}

async function login(email, password) {
    const form = await pageToken("/signin");
    const result = await request("/signin", {
        method: "POST",
        headers: { cookie: form.cookie },
        body: formBody({ email, password, _csrf: form.token })
    });
    assert.equal(result.response.status, 302);
    return cookieFrom(result.response);
}

function createUser(email, password) {
    db.prepare(
        "INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)"
    ).run("Validation Test User", email, bcrypt.hashSync(password, 10), "borrower");
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

test("validates account, loan, and repayment fields without changing valid financial calculations", async () => {
    const email = `validation-${Date.now()}@example.test`;
    const password = "Validation-Password-123!";
    createUser(email, password);
    const cookie = await login(email, password);
    const loanForm = await pageToken("/request-loan", cookie);
    const initialLoanCount = db.prepare("SELECT COUNT(*) AS count FROM loans").get().count;

    const invalidLoan = await request("/request-loan", {
        method: "POST",
        headers: { cookie },
        body: formBody({
            amount: "not-a-number",
            interestRate: "101",
            purpose: "x",
            _csrf: loanForm.token
        })
    });
    assert.equal(invalidLoan.response.status, 400);
    assert.equal(db.prepare("SELECT COUNT(*) AS count FROM loans").get().count, initialLoanCount);

    const validZeroInterestLoan = await request("/request-loan", {
        method: "POST",
        headers: { cookie },
        body: formBody({
            amount: "1",
            interestRate: "0",
            purpose: "Small valid loan",
            _csrf: loanForm.token
        })
    });
    assert.equal(validZeroInterestLoan.response.status, 200);
    const loan = db.prepare("SELECT amount, interest_amount, total_repayment FROM loans ORDER BY id DESC LIMIT 1").get();
    assert.deepEqual(loan, { amount: 1, interest_amount: 0, total_repayment: 1 });

    const repaymentForm = await pageToken("/repayments", cookie);
    const invalidRepayment = await request("/repayments", {
        method: "POST",
        headers: { cookie },
        body: formBody({ loanId: "1.5", amount: "NaN", _csrf: repaymentForm.token })
    });
    assert.equal(invalidRepayment.response.status, 400);

    const signupForm = await pageToken("/signup");
    const invalidSignup = await request("/signup", {
        method: "POST",
        headers: { cookie: signupForm.cookie },
        body: formBody({
            name: "N".repeat(101),
            email: "not-an-email",
            password: "p".repeat(129),
            confirmPassword: "p".repeat(129),
            _csrf: signupForm.token
        })
    });
    assert.equal(invalidSignup.response.status, 400);
});

test("rejects URL-encoded bodies larger than 50 KB with a generic 413 response", async () => {
    const form = await pageToken("/signin");
    const oversized = await request("/signin", {
        method: "POST",
        headers: { cookie: form.cookie },
        body: formBody({
            email: "large@example.test",
            password: "x".repeat(60_000),
            _csrf: form.token
        })
    });
    assert.equal(oversized.response.status, 413);
    assert.equal(oversized.text, "Request is too large.");
});

test("rate-limits repeated failed sign-in attempts without exposing account details", async () => {
    const email = `rate-limit-${Date.now()}@example.test`;
    createUser(email, "Correct-Password-123!");
    const form = await pageToken("/signin");

    for (let attempt = 0; attempt < 5; attempt += 1) {
        const failed = await request("/signin", {
            method: "POST",
            headers: { cookie: form.cookie },
            body: formBody({ email, password: "Wrong-Password-123!", _csrf: form.token })
        });
        assert.equal(failed.response.status, 200);
        assert.equal(failed.text, "Invalid email or password.");
    }

    const limited = await request("/signin", {
        method: "POST",
        headers: { cookie: form.cookie },
        body: formBody({ email, password: "Wrong-Password-123!", _csrf: form.token })
    });
    assert.equal(limited.response.status, 429);
    assert.equal(limited.text, "Too many sign-in attempts. Please try again later.");
    assert.doesNotMatch(limited.text, new RegExp(email, "i"));
});
