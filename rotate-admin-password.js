require("dotenv").config();

const fs = require("fs");
const path = require("path");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");

const databasePath = process.env.DATABASE_PATH || "./database/microloan.db";
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
    const existingAdmin = db.prepare(`
        SELECT id
        FROM users
        WHERE lower(email) = lower(?) AND role = 'admin'
    `).get(email);

    if (!existingAdmin) {
        console.error("Administrator password rotation stopped: no administrator account was found for the configured email.");
        process.exitCode = 1;
    } else {
        const hashedPassword = bcrypt.hashSync(password, 10);
        db.transaction(() => {
            db.prepare(`
                UPDATE users
                SET password = ?
                WHERE id = ? AND role = 'admin'
            `).run(hashedPassword, existingAdmin.id);
            db.prepare(`
                INSERT INTO audit_logs (
                    actor_user_id, actor_role, event_type, target_type, target_id, metadata
                ) VALUES (?, ?, ?, ?, ?, ?)
            `).run(
                existingAdmin.id,
                "admin",
                "admin.password.rotate",
                "user",
                existingAdmin.id,
                JSON.stringify({ source: "explicit-rotation" })
            );
        })();
        console.log("Administrator password rotated successfully.");
    }
} catch (error) {
    console.error("Administrator password rotation failed.");
    process.exitCode = 1;
} finally {
    db.close();
}
