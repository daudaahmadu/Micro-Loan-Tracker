const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const http = require("node:http");
const { once } = require("node:events");
const { spawnSync } = require("node:child_process");
const bcrypt = require("bcryptjs");

const repositoryDirectory = path.join(__dirname, "..");
const temporaryDirectory = fs.mkdtempSync(
    path.join(os.tmpdir(), "micro-loan-tracker-session-")
);
process.env.DATABASE_PATH = path.join(temporaryDirectory, "test.sqlite");
process.env.SESSION_SECRET = "test-only-session-security-secret-which-is-long-enough";
process.env.NODE_ENV = "test";
process.env.REDIS_URL ||= "redis://127.0.0.1:6380/15";
process.env.REDIS_KEY_PREFIX ||= `mlt:test:session:${process.pid}:`;

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
    return {
        oldCookie: form.cookie,
        cookie: cookieFrom(result.response)
    };
}

function createUser(email, password) {
    const result = db.prepare(
        "INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)"
    ).run("Session Test Borrower", email, bcrypt.hashSync(password, 10), "borrower");
    return Number(result.lastInsertRowid);
}

function runModuleWithEnvironment(overrides = {}, source = `
    const loaded = require('./server');
    loaded.redisReady.then(async () => {
        console.log(JSON.stringify({
            secure: loaded.sessionCookieOptions.secure,
            httpOnly: loaded.sessionCookieOptions.httpOnly,
            sameSite: loaded.sessionCookieOptions.sameSite,
            maxAge: loaded.sessionCookieOptions.maxAge,
            trustProxy: loaded.app.get('trust proxy')
        }));
        loaded.db.close();
        await loaded.redisClient.quit();
    }).catch(() => {
        process.exitCode = 1;
    });
`) {
    const environment = { ...process.env, ...overrides };
    if (overrides.SESSION_SECRET === undefined && Object.prototype.hasOwnProperty.call(overrides, "SESSION_SECRET")) {
        delete environment.SESSION_SECRET;
    }
    return spawnSync(process.execPath, ["-e", source], {
        cwd: repositoryDirectory,
        env: environment,
        encoding: "utf8"
    });
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

test("rejects missing, short, and placeholder SESSION_SECRET values without exposing secrets", () => {
    const cases = [
        { name: "missing", overrides: { SESSION_SECRET: undefined } },
        { name: "short", overrides: { SESSION_SECRET: "too-short" } },
        { name: "placeholder", overrides: { SESSION_SECRET: "change-me" } }
    ];

    for (const item of cases) {
        const result = runModuleWithEnvironment({
            ...item.overrides,
            DATABASE_PATH: path.join(temporaryDirectory, `${item.name}.sqlite`),
            NODE_ENV: "production"
        });
        assert.notEqual(result.status, 0, `${item.name} secret should fail startup`);
        assert.doesNotMatch(
            `${result.stdout}\n${result.stderr}`,
            /too-short|change-me|test-only-session-security-secret/i,
            `${item.name} secret must not be exposed`
        );
    }
});

test("uses secure production cookie settings and trusts one Render proxy hop", () => {
    const productionSecret = "production-only-session-security-secret-long-enough";
    const result = runModuleWithEnvironment({
        SESSION_SECRET: productionSecret,
        DATABASE_PATH: path.join(temporaryDirectory, "production-config.sqlite"),
        NODE_ENV: "production",
        REDIS_URL: "rediss://127.0.0.1:6380/15"
    }, `
        const loaded = require('./server');
        console.log(JSON.stringify({
            secure: loaded.sessionCookieOptions.secure,
            httpOnly: loaded.sessionCookieOptions.httpOnly,
            sameSite: loaded.sessionCookieOptions.sameSite,
            maxAge: loaded.sessionCookieOptions.maxAge,
            trustProxy: loaded.app.get('trust proxy')
        }));
        loaded.redisReady.catch(() => {});
        loaded.db.close();
        loaded.redisClient.disconnect();
    `);
    assert.equal(result.status, 0, result.stderr);
    const output = result.stdout.trim().split("\n").at(-1);
    const config = JSON.parse(output);
    assert.equal(config.secure, true);
    assert.equal(config.httpOnly, true);
    assert.equal(config.sameSite, "lax");
    assert.equal(config.maxAge, 8 * 60 * 60 * 1000);
    assert.equal(config.trustProxy, 1);
    assert.doesNotMatch(result.stdout, new RegExp(productionSecret));
    assert.doesNotMatch(result.stderr, new RegExp(productionSecret));
});

test("sets explicit cookie attributes, regenerates login sessions, protects routes, and clears logout cookies", async () => {
    const email = `session-${Date.now()}@example.test`;
    const password = "Session-Password-123!";
    createUser(email, password);

    const signinPage = await request("/signin");
    const preLoginCookie = cookieFrom(signinPage.response);
    const preLoginToken = tokenFrom(signinPage.text);
    const initialCookieHeader = signinPage.response.headers.get("set-cookie");
    assert.match(initialCookieHeader, /HttpOnly/);
    assert.match(initialCookieHeader, /SameSite=Lax/);
    assert.match(initialCookieHeader, /Expires=/);
    assert.doesNotMatch(initialCookieHeader, /Secure/);

    const loginResponse = await request("/signin", {
        method: "POST",
        headers: { cookie: preLoginCookie },
        body: formBody({ email, password, _csrf: preLoginToken })
    });
    assert.equal(loginResponse.response.status, 302);
    const authenticatedCookie = cookieFrom(loginResponse.response);
    assert.ok(authenticatedCookie);
    assert.notEqual(authenticatedCookie, preLoginCookie);

    const authenticatedPage = await pageToken("/dashboard", authenticatedCookie);
    assert.notEqual(authenticatedPage.token, preLoginToken);
    assert.equal((await request("/dashboard", { headers: { cookie: authenticatedCookie } })).response.status, 200);
    assert.equal((await request("/my-loans", { headers: { cookie: authenticatedCookie } })).response.status, 200);
    assert.equal((await request("/repayments", { headers: { cookie: authenticatedCookie } })).response.status, 200);
    assert.equal((await request("/request-loan", { headers: { cookie: authenticatedCookie } })).response.status, 200);
    assert.equal((await request("/admin-dashboard", { headers: { cookie: authenticatedCookie } })).response.status, 403);
    assert.equal((await request("/dashboard", { headers: { cookie: preLoginCookie } })).response.status, 302);

    const logout = await request("/logout", {
        method: "POST",
        headers: { cookie: authenticatedCookie },
        body: formBody({ _csrf: authenticatedPage.token })
    });
    assert.equal(logout.response.status, 302);
    assert.equal(logout.response.headers.get("location"), "/signin");
    assert.match(logout.response.headers.get("set-cookie"), /Expires=Thu, 01 Jan 1970/);
    assert.equal((await request("/dashboard", { headers: { cookie: authenticatedCookie } })).response.status, 302);
});

test("unauthenticated users are redirected from protected borrower and administrator routes", async () => {
    for (const pathname of ["/dashboard", "/my-loans", "/repayments", "/request-loan", "/admin-dashboard"]) {
        const result = await request(pathname);
        assert.equal(result.response.status, 302, pathname);
        assert.equal(result.response.headers.get("location"), "/signin", pathname);
    }
});
