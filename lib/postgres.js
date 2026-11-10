const fs = require("node:fs");
const path = require("node:path");
const { Pool } = require("pg");

const DEFAULT_POOL_MAX = 10;
const DEFAULT_IDLE_TIMEOUT_MS = 30_000;
const DEFAULT_CONNECTION_TIMEOUT_MS = 5_000;

function boundedInteger(value, fallback, minimum, maximum) {
    const parsed = Number.parseInt(value, 10);
    if (!Number.isInteger(parsed)) return fallback;
    return Math.min(Math.max(parsed, minimum), maximum);
}

function createPostgresDatabase({ connectionString = process.env.DATABASE_URL } = {}) {
    if (typeof connectionString !== "string" || connectionString.trim() === "") {
        return null;
    }

    const pool = new Pool({
        connectionString,
        max: boundedInteger(process.env.PG_POOL_MAX, DEFAULT_POOL_MAX, 1, 50),
        idleTimeoutMillis: boundedInteger(
            process.env.PG_IDLE_TIMEOUT_MS,
            DEFAULT_IDLE_TIMEOUT_MS,
            1_000,
            300_000
        ),
        connectionTimeoutMillis: boundedInteger(
            process.env.PG_CONNECTION_TIMEOUT_MS,
            DEFAULT_CONNECTION_TIMEOUT_MS,
            500,
            60_000
        ),
        maxUses: boundedInteger(process.env.PG_MAX_USES, 0, 0, 100_000) || undefined
    });

    pool.on("error", () => {
        // Do not expose connection details or credentials from idle-client errors.
    });

    return {
        pool,
        query(text, values) {
            return pool.query(text, values);
        },
        async transaction(callback) {
            const client = await pool.connect();
            try {
                await client.query("BEGIN");
                const result = await callback(client);
                await client.query("COMMIT");
                return result;
            } catch (error) {
                try {
                    await client.query("ROLLBACK");
                } catch {
                    // Preserve the original transaction error.
                }
                throw error;
            } finally {
                client.release();
            }
        },
        async initializeSchema() {
            const schemaPath = path.join(__dirname, "..", "db", "postgres-schema.sql");
            await pool.query(fs.readFileSync(schemaPath, "utf8"));
        },
        async close() {
            await pool.end();
        }
    };
}

module.exports = {
    createPostgresDatabase,
    boundedInteger,
    DEFAULT_POOL_MAX,
    DEFAULT_IDLE_TIMEOUT_MS,
    DEFAULT_CONNECTION_TIMEOUT_MS
};
