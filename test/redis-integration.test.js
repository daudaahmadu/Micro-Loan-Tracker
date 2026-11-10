const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawn, spawnSync } = require("node:child_process");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");

const repositoryDirectory = path.join(__dirname, "..");
const temporaryDirectory = fs.mkdtempSync(
    path.join(os.tmpdir(), "micro-loan-tracker-redis-")
);
const redisPort = 6381;
const appPortA = 4311;
const appPortB = 4312;
const appPortC = 4313;
const redisUrl = `redis://127.0.0.1:${redisPort}/15`;
const redisKeyPrefix = `mlt:integration:${process.pid}:`;
const databasePath = path.join(temporaryDirectory, "test.sqlite");
const sessionSecret = "redis-integration-session-secret-long-enough";
let redisProcess;
const appProcesses = [];

function sleep(milliseconds) {
    return new Promise(resolve => setTimeout(resolve, milliseconds));
}

async function waitFor(check, timeout = 8000) {
    const deadline = Date.now() + timeout;
    let lastError;
    while (Date.now() < deadline) {
        try {
            if (await check()) {
                return;
            }
        } catch (error) {
            lastError = error;
        }
        await sleep(50);
    }
    throw lastError || new Error("Timed out waiting for test service.");
}

function startRedis() {
    redisProcess = spawn("redis-server", [
        "--bind", "127.0.0.1",
        "--port", String(redisPort),
        "--dir", temporaryDirectory,
        "--appendonly", "yes",
        "--save", ""
    ], { stdio: "ignore" });
    return waitFor(() => {
        const result = spawnSync("redis-cli", ["-p", String(redisPort), "PING"], {
            encoding: "utf8"
        });
        return result.status === 0 && result.stdout.trim() === "PONG";
    });
}

function startApp(port) {
    const child = spawn(process.execPath, ["server.js"], {
        cwd: repositoryDirectory,
        env: {
            ...process.env,
            NODE_ENV: "test",
            PORT: String(port),
            DATABASE_PATH: databasePath,
            SESSION_SECRET: sessionSecret,
            REDIS_URL: redisUrl,
            REDIS_KEY_PREFIX: redisKeyPrefix
        },
        stdio: ["ignore", "pipe", "pipe"]
    });
    child.stdout.resume();
    child.stderr.resume();
    appProcesses.push(child);
    return waitFor(async () => {
        const response = await fetch(`http://127.0.0.1:${port}/signin`);
        return response.status === 200;
    }).then(() => child);
}

async function stopProcess(child) {
    if (!child || child.exitCode !== null) {
        return;
    }
    child.kill("SIGTERM");
    await Promise.race([
        new Promise(resolve => child.once("exit", resolve)),
        sleep(2000)
    ]);
    if (child.exitCode === null) {
        child.kill("SIGKILL");
    }
}

function cookieFrom(response) {
    return response.headers.get("set-cookie")?.split(";", 1)[0];
}

function tokenFrom(text) {
    const match = text.match(/name="_csrf" value="([a-f0-9]{64})"/);
    assert.ok(match, "expected CSRF token");
    return match[1];
}

async function loginAt(port, email, password) {
    const signin = await fetch(`http://127.0.0.1:${port}/signin`);
    const signinText = await signin.text();
    const cookie = cookieFrom(signin);
    const login = await fetch(`http://127.0.0.1:${port}/signin`, {
        method: "POST",
        redirect: "manual",
        headers: {
            cookie,
            "content-type": "application/x-www-form-urlencoded"
        },
        body: new URLSearchParams({
            email,
            password,
            _csrf: tokenFrom(signinText)
        })
    });
    return { response: login, cookie: cookieFrom(login) };
}

function seedDatabase(email, password) {
    const db = new Database(databasePath);
    db.exec(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'borrower',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);
    db.prepare(
        "INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)"
    ).run("Redis Integration User", email, bcrypt.hashSync(password, 10), "borrower");
    db.close();
}

test.before(async () => {
    await startRedis();
    seedDatabase("redis-integration@example.test", "Redis-Integration-Password-123!");
});

test.after(async () => {
    for (const child of appProcesses.reverse()) {
        await stopProcess(child);
    }
    await stopProcess(redisProcess);
    fs.rmSync(temporaryDirectory, { recursive: true, force: true });
});

test("persists sessions across app restarts and shares sessions between instances", async () => {
    const instanceA = await startApp(appPortA);
    const instanceB = await startApp(appPortB);
    const login = await loginAt(appPortA, "redis-integration@example.test", "Redis-Integration-Password-123!");
    assert.equal(login.response.status, 302);
    assert.ok(login.cookie);

    const shared = await fetch(`http://127.0.0.1:${appPortB}/dashboard`, {
        redirect: "manual",
        headers: { cookie: login.cookie }
    });
    assert.equal(shared.status, 200, "instance B should read instance A's session");

    await stopProcess(instanceA);
    const instanceC = await startApp(appPortC);
    const afterRestart = await fetch(`http://127.0.0.1:${appPortC}/dashboard`, {
        redirect: "manual",
        headers: { cookie: login.cookie }
    });
    assert.equal(afterRestart.status, 200, "a restarted app should read the Redis session");
});

test("shares login rate limits across application instances", async () => {
    for (let attempt = 0; attempt < 3; attempt += 1) {
        const failed = await loginAt(appPortB, "redis-integration@example.test", "Wrong-Password-123!");
        assert.equal(failed.response.status, 200);
    }
    for (let attempt = 0; attempt < 2; attempt += 1) {
        const failed = await loginAt(appPortC, "redis-integration@example.test", "Wrong-Password-123!");
        assert.equal(failed.response.status, 200);
    }
    const limited = await loginAt(appPortB, "redis-integration@example.test", "Wrong-Password-123!");
    assert.equal(limited.response.status, 429);
});

test("atomically enforces the limit for concurrent attempts across instances", async () => {
    const results = await Promise.all(
        Array.from({ length: 12 }, (_, index) => loginAt(
            index % 2 === 0 ? appPortB : appPortC,
            "concurrent-rate-limit@example.test",
            "Wrong-Password-123!"
        ))
    );
    const statuses = results.map(result => result.response.status);
    const acceptedFailures = statuses.filter(status => status === 200).length;
    const rejectedAttempts = statuses.filter(status => status === 429).length;

    assert.equal(acceptedFailures, 5);
    assert.equal(rejectedAttempts, 7);
    assert.deepEqual(
        statuses.sort((left, right) => left - right),
        [200, 200, 200, 200, 200, 429, 429, 429, 429, 429, 429, 429]
    );
});

test("fails closed during Redis outage and recovers after Redis reconnects", async () => {
    spawnSync("redis-cli", ["-p", String(redisPort), "SHUTDOWN", "NOSAVE"], {
        encoding: "utf8"
    });
    await sleep(250);

    const unavailable = await fetch(`http://127.0.0.1:${appPortB}/signin`);
    assert.equal(unavailable.status, 503);

    await startRedis();
    await waitFor(async () => {
        const response = await fetch(`http://127.0.0.1:${appPortB}/signin`);
        return response.status === 200;
    });
});

test("requires REDIS_URL and rejects invalid Redis configuration", () => {
    const source = "require('./server')";
    const baseEnvironment = {
        ...process.env,
        NODE_ENV: "production",
        SESSION_SECRET: sessionSecret,
        DATABASE_PATH: path.join(temporaryDirectory, "startup.sqlite")
    };
    delete baseEnvironment.REDIS_URL;
    const missing = spawnSync(process.execPath, ["-e", source], {
        cwd: repositoryDirectory,
        env: baseEnvironment,
        encoding: "utf8"
    });
    assert.notEqual(missing.status, 0);
    assert.doesNotMatch(`${missing.stdout}\n${missing.stderr}`, /rediss?:\/\/|token|password/i);

    const invalid = spawnSync(process.execPath, ["-e", source], {
        cwd: repositoryDirectory,
        env: { ...baseEnvironment, REDIS_URL: "not-a-redis-url" },
        encoding: "utf8"
    });
    assert.notEqual(invalid.status, 0);
    assert.doesNotMatch(`${invalid.stdout}\n${invalid.stderr}`, /not-a-redis-url|token|password/i);

    const nonTlsProduction = spawnSync(process.execPath, ["-e", source], {
        cwd: repositoryDirectory,
        env: { ...baseEnvironment, REDIS_URL: "redis://127.0.0.1:6381/15" },
        encoding: "utf8"
    });
    assert.notEqual(nonTlsProduction.status, 0);
    assert.doesNotMatch(`${nonTlsProduction.stdout}\n${nonTlsProduction.stderr}`, /redis:\/\/127|token|password/i);
});
