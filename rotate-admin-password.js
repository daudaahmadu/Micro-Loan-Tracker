require("dotenv").config();
const fs = require("node:fs");
const path = require("node:path");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const { createPostgresDatabase } = require("./lib/postgres");
const databasePath = process.env.DATABASE_PATH || "./database/microloan.db";
const email = typeof process.env.ADMIN_EMAIL === "string" ? process.env.ADMIN_EMAIL.trim().toLowerCase() : "";
const password = process.env.ADMIN_PASSWORD;
function validEmail(value) { return value.length >= 3 && value.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value); }
if (!validEmail(email) || typeof password !== "string" || password.length < 6 || password.length > 128) { console.error("ADMIN_EMAIL and ADMIN_PASSWORD must be valid administrator credentials."); process.exit(1); }
(async () => {
    const postgres = createPostgresDatabase();
    if (postgres) {
        try { await postgres.initializeSchema(); const hash = bcrypt.hashSync(password, 10); await postgres.transaction(async client => { const found = (await client.query("SELECT id FROM users WHERE lower(email)=lower($1) AND role='admin' FOR UPDATE", [email])).rows[0]; if (!found) throw new Error("no administrator"); await client.query("UPDATE users SET password=$1 WHERE id=$2 AND role='admin'", [hash, found.id]); await client.query("INSERT INTO audit_logs (actor_user_id, actor_role, event_type, target_type, target_id, metadata) VALUES ($1,'admin','admin.password.rotate','user',$1,$2::jsonb)", [found.id, JSON.stringify({ source: "explicit-rotation" })]); }); console.log("Administrator password rotated successfully."); }
        catch { console.error("Administrator password rotation failed."); process.exitCode = 1; } finally { await postgres.close(); } return;
    }
    fs.mkdirSync(path.dirname(databasePath), { recursive: true }); const db = new Database(databasePath);
    try { db.exec("CREATE TABLE IF NOT EXISTS audit_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, actor_user_id INTEGER, actor_role TEXT, event_type TEXT NOT NULL, target_type TEXT, target_id INTEGER, metadata TEXT, ip_hash TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)"); const found = db.prepare("SELECT id FROM users WHERE lower(email)=lower(?) AND role='admin'").get(email); if (!found) throw new Error("no administrator"); const hash = bcrypt.hashSync(password, 10); db.transaction(() => { db.prepare("UPDATE users SET password=? WHERE id=? AND role='admin'").run(hash, found.id); db.prepare("INSERT INTO audit_logs (actor_user_id, actor_role, event_type, target_type, target_id, metadata) VALUES (?, 'admin', 'admin.password.rotate', 'user', ?, ?)").run(found.id, found.id, JSON.stringify({ source: "explicit-rotation" })); })(); console.log("Administrator password rotated successfully."); }
    catch { console.error("Administrator password rotation failed."); process.exitCode = 1; } finally { db.close(); }
})().catch(() => { console.error("Administrator password rotation failed."); process.exitCode = 1; });
