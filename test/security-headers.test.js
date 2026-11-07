const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const http = require("node:http");
const { once } = require("node:events");
const bcrypt = require("bcryptjs");

const temporaryDirectory = fs.mkdtempSync(
    path.join(os.tmpdir(), "micro-loan-tracker-headers-")
);
process.env.DATABASE_PATH = path.join(temporaryDirectory, "test.sqlite");
process.env.SESSION_SECRET = "test-only-security-headers-secret-long-enough";
process.env.NODE_ENV = "test";
process.env.REDIS_URL ||= "redis://127.0.0.1:6380/15";
process.env.REDIS_KEY_PREFIX ||= `mlt:test:headers:${process.pid}:`;

const { app, db, redisClient, redisReady, shouldUseHsts } = require("../server");

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

async function login(email, password) {
    const signInPage = await request("/signin");
    const signInCookie = cookieFrom(signInPage.response);
    const result = await request("/signin", {
        method: "POST",
        headers: { cookie: signInCookie },
        body: formBody({
            email,
            password,
            _csrf: tokenFrom(signInPage.text)
        })
    });
    assert.equal(result.response.status, 302);
    return cookieFrom(result.response);
}

function createUser(name, email, password, role) {
    const result = db.prepare(
        "INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)"
    ).run(name, email, bcrypt.hashSync(password, 10), role);
    return Number(result.lastInsertRowid);
}

const expectedHeaders = {
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=(), microphone=(), geolocation=()",
    "content-security-policy": "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'"
};

function assertSecurityHeaders(response) {
    for (const [name, value] of Object.entries(expectedHeaders)) {
        assert.equal(response.headers.get(name), value, `${name} header`);
    }
}

test.before(async () => {
    await redisReady;
    createUser(
        "Header Borrower",
        "header-borrower@example.test",
        "Header-Password-123!",
        "borrower"
    );
    createUser(
        "Header Administrator",
        "header-admin@example.test",
        "Header-Admin-123!",
        "admin"
    );
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

test("sets baseline security headers on public and static responses", async () => {
    const home = await request("/");
    assert.equal(home.response.status, 200);
    assertSecurityHeaders(home.response);
    assert.equal(home.response.headers.get("content-security-policy-report-only"), null);
    assert.equal(home.response.headers.get("strict-transport-security"), null);
    assert.notEqual(home.response.headers.get("cache-control"), "no-store");

    const css = await request("/style.css");
    assert.equal(css.response.status, 200);
    assertSecurityHeaders(css.response);
});

test("sets no-store on authenticated borrower and administrator pages", async () => {
    const borrowerCookie = await login(
        "header-borrower@example.test",
        "Header-Password-123!"
    );
    const borrower = await request("/dashboard", {
        headers: { cookie: borrowerCookie }
    });
    assert.equal(borrower.response.status, 200);
    assertSecurityHeaders(borrower.response);
    assert.equal(borrower.response.headers.get("cache-control"), "no-store");

    const adminCookie = await login(
        "header-admin@example.test",
        "Header-Admin-123!"
    );
    const admin = await request("/admin-dashboard", {
        headers: { cookie: adminCookie }
    });
    assert.equal(admin.response.status, 200);
    assertSecurityHeaders(admin.response);
    assert.equal(admin.response.headers.get("cache-control"), "no-store");
});

test("does not enable HSTS for non-production requests even with forwarded HTTPS", async () => {
    const response = await request("/signin", {
        headers: { "x-forwarded-proto": "https" }
    });
    assert.equal(response.response.status, 200);
    assert.equal(response.response.headers.get("strict-transport-security"), null);
});

test("enables HSTS only when production HTTPS is verified", () => {
    assert.equal(shouldUseHsts({ secure: false }, true), false);
    assert.equal(shouldUseHsts({ secure: true }, false), false);
    assert.equal(shouldUseHsts({ secure: true }, true), true);
});
