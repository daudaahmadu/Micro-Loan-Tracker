#!/usr/bin/env node
/* Synthetic/local data only. Production environments and unapproved paths are rejected. */
const fs = require("node:fs");
const path = require("node:path");
const Database = require("better-sqlite3");
const { createPostgresDatabase } = require("../lib/postgres");

const tables = ["users", "loans", "repayments", "audit_logs"];
const sequences = {
    users: "users_id_seq",
    loans: "loans_id_seq",
    repayments: "repayments_id_seq",
    audit_logs: "audit_logs_id_seq"
};

function guard() {
    if (process.env.NODE_ENV === "production" || process.env.ALLOW_SYNTHETIC_MIGRATION !== "1") {
        throw new Error("Refusing migration: set NODE_ENV=development/test and ALLOW_SYNTHETIC_MIGRATION=1.");
    }
    if (!process.env.SOURCE_SQLITE_PATH || !process.env.DATABASE_URL) {
        throw new Error("SOURCE_SQLITE_PATH and DATABASE_URL are required.");
    }
    const sourcePath = path.resolve(process.env.SOURCE_SQLITE_PATH);
    if (sourcePath.includes(`${path.sep}database${path.sep}`)) {
        throw new Error("Refusing migration against the default database directory.");
    }
}

function readSource() {
    const db = new Database(process.env.SOURCE_SQLITE_PATH, { readonly: true });
    try {
        return Object.fromEntries(
            tables.map(table => [table, db.prepare(`SELECT * FROM ${table}`).all()])
        );
    } finally {
        db.close();
    }
}

function writeJson(file, payload) {
    if (!file || path.resolve(file) === path.resolve(process.env.SOURCE_SQLITE_PATH)) {
        throw new Error("Unsafe export/restore path.");
    }
    fs.writeFileSync(file, `${JSON.stringify(payload, null, 2)}\n`, {
        flag: "wx",
        mode: 0o600
    });
}

function parseMetadata(value) {
    if (value === null || value === undefined || value === "") return null;
    return typeof value === "string" ? JSON.parse(value) : value;
}

async function restore(client, payload) {
    for (const table of [...tables].reverse()) {
        await client.query(`TRUNCATE ${table} RESTART IDENTITY CASCADE`);
    }
    for (const row of payload.users) {
        await client.query(
            "INSERT INTO users (id,name,email,password,role,created_at) VALUES ($1,$2,$3,$4,$5,$6)",
            [row.id, row.name, row.email, row.password, row.role, row.created_at]
        );
    }
    for (const row of payload.loans) {
        await client.query(
            "INSERT INTO loans (id,user_id,amount,interest_rate,interest_amount,total_repayment,purpose,status,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
            [row.id, row.user_id, row.amount, row.interest_rate, row.interest_amount, row.total_repayment, row.purpose, row.status, row.created_at]
        );
    }
    for (const row of payload.repayments) {
        await client.query(
            "INSERT INTO repayments (id,loan_id,user_id,amount,idempotency_key,payment_date) VALUES ($1,$2,$3,$4,$5,$6)",
            [row.id, row.loan_id, row.user_id, row.amount, row.idempotency_key || null, row.payment_date]
        );
    }
    for (const row of payload.audit_logs) {
        await client.query(
            "INSERT INTO audit_logs (id,actor_user_id,actor_role,event_type,target_type,target_id,metadata,ip_hash,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
            [row.id, row.actor_user_id, row.actor_role, row.event_type, row.target_type, row.target_id, parseMetadata(row.metadata), row.ip_hash, row.created_at]
        );
    }
    for (const [table, sequence] of Object.entries(sequences)) {
        await client.query(
            `SELECT setval($1, GREATEST(COALESCE((SELECT MAX(id) FROM ${table}), 1), 1), true)`,
            [sequence]
        );
    }
}

async function main() {
    guard();
    const command = process.argv[2] || "reconcile";
    const postgres = createPostgresDatabase();
    try {
        await postgres.initializeSchema();
        if (command === "export") {
            writeJson(process.argv[3], readSource());
            console.log("Synthetic export written.");
            return;
        }
        if (command === "restore") {
            if (process.env.ALLOW_SYNTHETIC_RESTORE !== "1") {
                throw new Error("Set ALLOW_SYNTHETIC_RESTORE=1 for restore.");
            }
            const payload = JSON.parse(fs.readFileSync(process.argv[3], "utf8"));
            if (!tables.every(table => Array.isArray(payload[table]))) {
                throw new Error("Invalid export format.");
            }
            await postgres.transaction(client => restore(client, payload));
            console.log("Synthetic restore complete; no production data was touched.");
            return;
        }
        const source = readSource();
        const counts = {};
        for (const table of tables) {
            const result = await postgres.query(`SELECT COUNT(*)::int AS count FROM ${table}`);
            counts[table] = { source: source[table].length, target: result.rows[0].count };
        }
        console.log(JSON.stringify({ command: "reconcile", counts }));
    } finally {
        await postgres.close();
    }
}

main().catch(error => {
    console.error(error.message);
    process.exitCode = 1;
});
