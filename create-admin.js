require("dotenv").config();
const fs = require("node:fs");
const path = require("node:path");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const { createPostgresDatabase } = require("./lib/postgres");

const databasePath = process.env.DATABASE_PATH || "./database/microloan.db";
if (process.env.NODE_ENV === "production" && (!process.env.DATABASE_URL || !process.env.DATABASE_URL.trim())) { console.error("DATABASE_URL must be configured in production; refusing SQLite fallback."); process.exit(1); }
const name = "Micro-Loan Admin";
const email = typeof process.env.ADMIN_EMAIL === "string" ? process.env.ADMIN_EMAIL.trim().toLowerCase() : "";
const password = process.env.ADMIN_PASSWORD;
function validEmail(value) { return value.length >= 3 && value.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value); }
if (!validEmail(email) || typeof password !== "string" || password.length < 6 || password.length > 128) { console.error("ADMIN_EMAIL and ADMIN_PASSWORD must be valid administrator credentials."); process.exit(1); }

(async () => {
    const postgres = createPostgresDatabase();
    if (postgres) {
        try {
            await postgres.initializeSchema();
            const existing = (await postgres.query("SELECT id, role FROM users WHERE lower(email) = lower($1)", [email])).rows[0];
            if (existing) {
                if (existing.role !== "admin") throw new Error("Administrator bootstrap stopped: the configured email belongs to a non-administrator account.");
                console.log("Administrator already exists; no changes made.");
                return;
            }
            const hash = bcrypt.hashSync(password, 10);
            await postgres.transaction(async client => {
                const created = (await client.query("INSERT INTO users (name, email, password, role) VALUES ($1, $2, $3, 'admin') RETURNING id", [name, email, hash])).rows[0];
                await client.query("INSERT INTO audit_logs (actor_user_id, actor_role, event_type, target_type, target_id, metadata) VALUES ($1, 'admin', 'admin.bootstrap.create', 'user', $1, $2::jsonb)", [created.id, JSON.stringify({ source: "bootstrap" })]);
            });
            console.log("Administrator account created successfully.");
        } catch (error) { console.error(error.message.includes("non-administrator") ? error.message : "Administrator bootstrap failed."); process.exitCode = 1; }
        finally { await postgres.close(); }
        return;
    }
    fs.mkdirSync(path.dirname(databasePath), { recursive: true });
    const db = new Database(databasePath);
    try {
        db.exec("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, password TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'borrower')");
        db.exec("CREATE TABLE IF NOT EXISTS audit_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, actor_user_id INTEGER, actor_role TEXT, event_type TEXT NOT NULL, target_type TEXT, target_id INTEGER, metadata TEXT, ip_hash TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)");
        const existing = db.prepare("SELECT id, role FROM users WHERE lower(email) = lower(?)").get(email);
        if (existing) {
            if (existing.role !== "admin") throw new Error("Administrator bootstrap stopped: the configured email belongs to a non-administrator account.");
            console.log("Administrator already exists; no changes made.");
        } else {
            const hash = bcrypt.hashSync(password, 10);
            db.transaction(() => { const created = db.prepare("INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)").run(name, email, hash, "admin"); db.prepare("INSERT INTO audit_logs (actor_user_id, actor_role, event_type, target_type, target_id, metadata) VALUES (?, 'admin', 'admin.bootstrap.create', 'user', ?, ?)").run(created.lastInsertRowid, created.lastInsertRowid, JSON.stringify({ source: "bootstrap" })); })();
            console.log("Administrator account created successfully.");
        }
    } catch (error) { console.error(error.message.includes("non-administrator") ? error.message : "Administrator bootstrap failed."); process.exitCode = 1; } finally { db.close(); }
})().catch(() => { console.error("Administrator bootstrap failed."); process.exitCode = 1; });
