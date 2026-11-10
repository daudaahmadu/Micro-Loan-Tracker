const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { Decimal, decimalString, formatNgn } = require("../lib/decimal");

const repo = path.join(__dirname, "..");

test("NGN decimal policy accepts four places and calculates without binary floating point", () => {
    assert.equal(decimalString("0.1"), "0.1");
    assert.equal(decimalString("0.29"), "0.29");
    assert.equal(decimalString("123.4567"), "123.4567");
    assert.equal(decimalString("123.45678"), null);
    assert.equal(new Decimal("0.1").plus("0.2").toString(), "0.3");
    assert.equal(new Decimal("12345678901234567890.1234").plus("0.8766").toString(), "12345678901234567891");
    assert.equal(new Decimal("123.4567").times("12.3456").toString(), "1524.14703552");
    assert.equal(formatNgn("123.4567"), "123.46");
});

test("production admin utilities refuse missing DATABASE_URL without creating SQLite", () => {
    for (const script of ["create-admin.js", "rotate-admin-password.js"]) {
        const dir = fs.mkdtempSync(path.join(os.tmpdir(), "micro-loan-fail-closed-"));
        const databasePath = path.join(dir, "should-not-exist.sqlite");
        const result = spawnSync(process.execPath, [script], {
            cwd: repo,
            encoding: "utf8",
            env: { ...process.env, NODE_ENV: "production", DATABASE_URL: "", DATABASE_PATH: databasePath, ADMIN_EMAIL: "admin@example.test", ADMIN_PASSWORD: "Admin-Password-123!" }
        });
        assert.notEqual(result.status, 0, `${script} unexpectedly succeeded`);
        assert.equal(fs.existsSync(databasePath), false);
        fs.rmSync(dir, { recursive: true, force: true });
    }
});
