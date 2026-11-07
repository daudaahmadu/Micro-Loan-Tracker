require("dotenv").config();

const fs = require("fs");
const path = require("path");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");

const databasePath = process.env.DATABASE_PATH || "./database/microloan.db";
const name = "Micro-Loan Admin";
const email = typeof process.env.ADMIN_EMAIL === "string"
    ? process.env.ADMIN_EMAIL.trim().toLowerCase()
    : "";
const password = process.env.ADMIN_PASSWORD;

function validEmail(value) {
    return value.length >= 3 &&
        value.length <= 254 &&
        /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

if (!validEmail(email) || typeof password !== "string" || password.length < 6 || password.length > 128) {
    console.error("ADMIN_EMAIL and ADMIN_PASSWORD must be valid administrator credentials.");
    process.exit(1);
}

fs.mkdirSync(path.dirname(databasePath), { recursive: true });
const db = new Database(databasePath);

try {
    db.prepare(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'borrower'
        )
    `).run();
    db.prepare(`
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_user_id INTEGER,
            actor_role TEXT,
            event_type TEXT NOT NULL,
            target_type TEXT,
            target_id INTEGER,
            metadata TEXT,
            ip_hash TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (actor_user_id) REFERENCES users(id)
        )
    `).run();

    const existingUser = db.prepare(`
        SELECT id, role
        FROM users
        WHERE lower(email) = lower(?)
    `).get(email);

    if (existingUser) {
        if (existingUser.role !== "admin") {
            console.error("Administrator bootstrap stopped: the configured email belongs to a non-administrator account.");
            process.exitCode = 1;
        } else {
            console.log("Administrator already exists; no changes made.");
        }
    } else {
        const hashedPassword = bcrypt.hashSync(password, 10);
        db.transaction(() => {
            const result = db.prepare(`
                INSERT INTO users (name, email, password, role)
                VALUES (?, ?, ?, ?)
            `).run(name, email, hashedPassword, "admin");
            db.prepare(`
                INSERT INTO audit_logs (
                    actor_user_id, actor_role, event_type, target_type, target_id, metadata
                ) VALUES (?, ?, ?, ?, ?, ?)
            `).run(
                result.lastInsertRowid,
                "admin",
                "admin.bootstrap.create",
                "user",
                result.lastInsertRowid,
                JSON.stringify({ source: "bootstrap" })
            );
        })();
        console.log("Administrator account created successfully.");
    }
} catch (error) {
    console.error("Administrator bootstrap failed.");
    process.exitCode = 1;
} finally {
    db.close();
}
