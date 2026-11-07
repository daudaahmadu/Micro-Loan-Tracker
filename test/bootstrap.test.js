const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");

const repositoryDirectory = path.join(__dirname, "..");
const temporaryDirectory = fs.mkdtempSync(
    path.join(os.tmpdir(), "micro-loan-tracker-bootstrap-")
);

function runScript(script, databasePath, email, password) {
    return spawnSync(process.execPath, [script], {
        cwd: repositoryDirectory,
        env: {
            ...process.env,
            DATABASE_PATH: databasePath,
            ADMIN_EMAIL: email,
            ADMIN_PASSWORD: password,
            NODE_ENV: "test"
        },
        encoding: "utf8"
    });
}

function openDatabase(databasePath) {
    return new Database(databasePath);
}

function createUsersTable(db) {
    db.exec(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'borrower'
        )
    `);
}

test.after(() => {
    fs.rmSync(temporaryDirectory, { recursive: true, force: true });
});

test("creates an administrator once and repeated bootstrap runs preserve all credentials and role fields", () => {
    const databasePath = path.join(temporaryDirectory, "new-admin.sqlite");
    const email = "admin@example.test";
    const firstPassword = "First-Admin-Password-123!";
    const secondPassword = "Second-Admin-Password-123!";

    const first = runScript("create-admin.js", databasePath, email, firstPassword);
    assert.equal(first.status, 0, first.stderr);
    assert.match(first.stdout, /created successfully/i);

    const db = openDatabase(databasePath);
    const created = db.prepare("SELECT name, email, password, role FROM users").get();
    assert.equal(created.name, "Micro-Loan Admin");
    assert.equal(created.email, email);
    assert.equal(created.role, "admin");
    assert.equal(bcrypt.compareSync(firstPassword, created.password), true);
    assert.equal(
        db.prepare("SELECT COUNT(*) AS count FROM audit_logs WHERE event_type = 'admin.bootstrap.create'").get().count,
        1
    );
    const originalHash = created.password;
    db.close();

    const second = runScript("create-admin.js", databasePath, email, secondPassword);
    assert.equal(second.status, 0, second.stderr);
    assert.match(second.stdout, /already exists; no changes made/i);

    const afterRepeat = openDatabase(databasePath);
    assert.equal(afterRepeat.prepare("SELECT COUNT(*) AS count FROM users").get().count, 1);
    const preserved = afterRepeat.prepare("SELECT name, email, password, role FROM users").get();
    assert.deepEqual(
        { name: preserved.name, email: preserved.email, role: preserved.role },
        { name: "Micro-Loan Admin", email, role: "admin" }
    );
    assert.equal(preserved.password, originalHash);
    assert.equal(bcrypt.compareSync(firstPassword, preserved.password), true);
    assert.equal(bcrypt.compareSync(secondPassword, preserved.password), false);
    assert.equal(
        afterRepeat.prepare("SELECT COUNT(*) AS count FROM audit_logs WHERE event_type = 'admin.bootstrap.create'").get().count,
        1
    );
    afterRepeat.close();
});

test("does not promote or modify an existing borrower whose email matches ADMIN_EMAIL", () => {
    const databasePath = path.join(temporaryDirectory, "existing-borrower.sqlite");
    const email = "existing-borrower@example.test";
    const password = "Borrower-Password-123!";
    const db = openDatabase(databasePath);
    createUsersTable(db);
    const hash = bcrypt.hashSync(password, 10);
    db.prepare("INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)")
        .run("Existing Borrower", email, hash, "borrower");
    db.close();

    const result = runScript("create-admin.js", databasePath, email, "Attempted-Admin-Password-123!");
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /non-administrator account/i);

    const after = openDatabase(databasePath);
    const borrower = after.prepare("SELECT name, email, password, role FROM users").get();
    assert.deepEqual(
        { name: borrower.name, email: borrower.email, role: borrower.role },
        { name: "Existing Borrower", email, role: "borrower" }
    );
    assert.equal(borrower.password, hash);
    assert.equal(after.prepare("SELECT COUNT(*) AS count FROM users").get().count, 1);
    after.close();
});

test("preserves an existing administrator and keeps password rotation explicit", () => {
    const databasePath = path.join(temporaryDirectory, "existing-admin.sqlite");
    const email = "existing-admin@example.test";
    const oldPassword = "Old-Admin-Password-123!";
    const bootstrapPassword = "Bootstrap-Password-Should-Not-Apply!";
    const rotatedPassword = "Rotated-Admin-Password-123!";
    const db = openDatabase(databasePath);
    createUsersTable(db);
    const originalHash = bcrypt.hashSync(oldPassword, 10);
    db.prepare("INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)")
        .run("Custom Administrator", email, originalHash, "admin");
    db.close();

    const bootstrap = runScript("create-admin.js", databasePath, email, bootstrapPassword);
    assert.equal(bootstrap.status, 0, bootstrap.stderr);
    const afterBootstrap = openDatabase(databasePath);
    const preserved = afterBootstrap.prepare("SELECT name, email, password, role FROM users").get();
    assert.equal(preserved.name, "Custom Administrator");
    assert.equal(preserved.email, email);
    assert.equal(preserved.role, "admin");
    assert.equal(preserved.password, originalHash);
    afterBootstrap.close();

    const rotation = runScript("rotate-admin-password.js", databasePath, email, rotatedPassword);
    assert.equal(rotation.status, 0, rotation.stderr);
    assert.match(rotation.stdout, /rotated successfully/i);

    const afterRotation = openDatabase(databasePath);
    const rotated = afterRotation.prepare("SELECT name, email, password, role FROM users").get();
    assert.equal(rotated.name, "Custom Administrator");
    assert.equal(rotated.email, email);
    assert.equal(rotated.role, "admin");
    assert.equal(bcrypt.compareSync(oldPassword, rotated.password), false);
    assert.equal(bcrypt.compareSync(rotatedPassword, rotated.password), true);
    assert.equal(
        afterRotation.prepare("SELECT COUNT(*) AS count FROM audit_logs WHERE event_type = 'admin.password.rotate'").get().count,
        1
    );
    const auditMetadata = afterRotation.prepare(
        "SELECT metadata FROM audit_logs WHERE event_type = 'admin.password.rotate'"
    ).get().metadata;
    assert.equal(auditMetadata.includes(rotatedPassword), false);
    afterRotation.close();
});

test("rotation refuses a borrower and does not modify that account", () => {
    const databasePath = path.join(temporaryDirectory, "rotation-borrower.sqlite");
    const email = "borrower-for-rotation@example.test";
    const password = "Borrower-Password-123!";
    const db = openDatabase(databasePath);
    createUsersTable(db);
    const hash = bcrypt.hashSync(password, 10);
    db.prepare("INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)")
        .run("Borrower", email, hash, "borrower");
    db.close();

    const result = runScript("rotate-admin-password.js", databasePath, email, "New-Password-123!");
    assert.notEqual(result.status, 0);

    const after = openDatabase(databasePath);
    const borrower = after.prepare("SELECT name, password, role FROM users").get();
    assert.equal(borrower.name, "Borrower");
    assert.equal(borrower.password, hash);
    assert.equal(borrower.role, "borrower");
    after.close();
});
