require("dotenv").config();
const express = require("express");
const crypto = require("crypto");
const path = require("path");
const Database = require("better-sqlite3");
const { createPostgresDatabase } = require("./lib/postgres");
const { createRepaymentRepository } = require("./lib/repayment-repository");
const { createDataRepository } = require("./lib/data-repository");
const { Decimal, decimalString, formatNgn, nonNegative } = require("./lib/decimal");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const { RedisStore } = require("connect-redis");
const { createClient } = require("redis");
const app = express();
const PORT = process.env.PORT || 3000;
const isProduction = process.env.NODE_ENV === "production";
const SESSION_MAX_AGE = 8 * 60 * 60 * 1000;
const MAX_REQUEST_BODY = "50kb";
const MAX_NAME_LENGTH = 100;
const MAX_EMAIL_LENGTH = 254;
const MAX_PASSWORD_LENGTH = 128;
const MAX_PURPOSE_LENGTH = 1000;
const MAX_LOAN_AMOUNT = 100_000_000;
const MAX_INTEREST_RATE = 100;
const MAX_REPAYMENT_AMOUNT = 100_000_000;
const LOGIN_RATE_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_RATE_MAX_FAILURES = 5;
const CSP_POLICY = [
    "default-src 'self'",
    "base-uri 'self'",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "form-action 'self'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self'",
    "connect-src 'self'"
].join("; ");
const AUDIT_EVENT_TYPES = new Set([
    "admin.signin.success",
    "admin.signin.failure",
    "admin.logout",
    "admin.authorization.denied",
    "admin.loan.approve",
    "admin.loan.reject",
    "admin.password.rotate",
    "admin.bootstrap.create",
    "loan.create",
    "repayment.create"
]);
function validateRedisUrl(value) {
    if (typeof value !== "string" || value.trim() === "") {
        throw new Error("REDIS_URL must be configured for the shared session store.");
    }
    let parsed;
    try {
        parsed = new URL(value);
    } catch (error) {
        throw new Error("REDIS_URL is invalid.");
    }
    if (!["redis:", "rediss:"].includes(parsed.protocol) || !parsed.hostname) {
        throw new Error("REDIS_URL must use a Redis URL.");
    }
    if (isProduction && parsed.protocol !== "rediss:") {
        throw new Error("Production REDIS_URL must use TLS.");
    }
    return value;
}

const REDIS_URL = validateRedisUrl(process.env.REDIS_URL);
const redisKeyPrefix = process.env.REDIS_KEY_PREFIX ||
    (process.env.NODE_ENV === "test" ? `mlt:test:${process.pid}:` : "mlt:");
const PLACEHOLDER_SESSION_SECRETS = new Set([
    "secret",
    "session_secret",
    "session-secret",
    "changeme",
    "change-me",
    "change-this",
    "default",
    "your-secret",
    "your-session-secret"
]);

function validateSessionSecret(secret) {
    const normalizedSecret = typeof secret === "string" ? secret.trim().toLowerCase() : "";
    if (
        typeof secret !== "string" ||
        secret.length < 32 ||
        PLACEHOLDER_SESSION_SECRETS.has(normalizedSecret)
    ) {
        throw new Error("SESSION_SECRET must be set to a non-placeholder value of at least 32 characters.");
    }
    return secret;
}

const sessionSecret = validateSessionSecret(process.env.SESSION_SECRET);

let redisClient;
try {
    redisClient = createClient({
        url: REDIS_URL,
        socket: {
            connectTimeout: 5000,
            reconnectStrategy: retries => retries > 4
                ? false
                : Math.min(Math.max(retries, 1) * 200, 1000)
        }
    });
} catch (error) {
    throw new Error("Redis client configuration is invalid.");
}
redisClient.on("error", () => {
    // Do not expose connection URLs, credentials, or internal Redis errors.
});
const redisReady = redisClient.connect().catch(() => {
    throw new Error("Redis shared store is unavailable.");
});

const sessionCookieOptions = {
    httpOnly: true,
    secure: isProduction,
    sameSite: "lax",
    maxAge: SESSION_MAX_AGE
};
app.set("trust proxy", isProduction ? 1 : false);

function escapeHtml(value) {
    return String(value ?? "").replace(/[&<>"']/g, character => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;"
    }[character]));
}
function createCsrfToken() {
    return crypto.randomBytes(32).toString("hex");
}

function ensureCsrfToken(req, res, next) {
    if (!req.session.csrfToken) {
        req.session.csrfToken = createCsrfToken();
    }
    next();
}

function csrfInput(req) {
    return `<input type="hidden" name="_csrf" value="${escapeHtml(req.session.csrfToken)}">`;
}

function renderCsrfPage(filePath, req) {
    return fs.readFileSync(filePath, "utf8")
        .replaceAll("<!-- CSRF_TOKEN -->", csrfInput(req));
}

function csrfProtection(req, res, next) {
    const submittedToken = req.body?._csrf;
    const sessionToken = req.session.csrfToken;

    if (
        typeof submittedToken !== "string" ||
        typeof sessionToken !== "string" ||
        submittedToken.length !== sessionToken.length ||
        !crypto.timingSafeEqual(
            Buffer.from(submittedToken),
            Buffer.from(sessionToken)
        )
    ) {
        return res.status(403).send("Invalid CSRF token.");
    }

    next();
}

function normalizedEmail(value) {
    if (typeof value !== "string") {
        return null;
    }
    const email = value.trim().toLowerCase();
    if (
        email.length < 3 ||
        email.length > MAX_EMAIL_LENGTH ||
        !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
    ) {
        return null;
    }
    return email;
}

function boundedText(value, maxLength) {
    if (typeof value !== "string") {
        return null;
    }
    const text = value.trim();
    return text.length > 0 && text.length <= maxLength ? text : null;
}

function numericField(value, maximum, { allowZero = true } = {}) {
    return decimalString(value, {
        positive: true,
        max: maximum,
        allowZero
    });
}

function positiveNumericField(value, maximum) {
    return numericField(value, maximum, { allowZero: false });
}

function positiveInteger(value) {
    if (typeof value !== "string" || !/^\d+$/.test(value)) {
        return null;
    }
    const number = Number(value);
    return Number.isSafeInteger(number) && number > 0 ? number : null;
}

function loginAttemptKey(req, email) {
    const material = `${req.ip}|${email || "invalid-email"}`;
    return `${redisKeyPrefix}login:${crypto.createHash("sha256").update(material).digest("hex")}`;
}

const LOGIN_RATE_LIMIT_SCRIPT = `
local current = tonumber(redis.call("GET", KEYS[1]) or "0")
if current >= tonumber(ARGV[1]) then
    return -1
end
local updated = redis.call("INCR", KEYS[1])
if updated == 1 then
    redis.call("EXPIRE", KEYS[1], tonumber(ARGV[2]))
end
return updated
`;

async function isLoginRateLimited(key) {
    const failures = Number(await redisClient.get(key) || 0);
    return Number.isSafeInteger(failures) && failures >= LOGIN_RATE_MAX_FAILURES;
}

async function recordLoginFailure(key) {
    return Number(await redisClient.eval(LOGIN_RATE_LIMIT_SCRIPT, {
        keys: [key],
        arguments: [
            String(LOGIN_RATE_MAX_FAILURES),
            String(Math.ceil(LOGIN_RATE_WINDOW_MS / 1000))
        ]
    }));
}

async function clearLoginFailures(key) {
    await redisClient.del(key);
}

function requireRedisAvailability(req, res, next) {
    if (req.path === "/health/ready") {
        return next();
    }
    if (!redisClient.isReady) {
        return res.status(503).send("Shared session service is temporarily unavailable.");
    }
    next();
}

function securityHeaders(req, res, next) {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
    res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
    res.setHeader("Content-Security-Policy", CSP_POLICY);

    if (shouldUseHsts(req)) {
        res.setHeader(
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains"
        );
    }

    next();
}

function shouldUseHsts(req, production = isProduction) {
    return production && req.secure === true;
}

function authenticatedCacheControl(req, res, next) {
    if (req.session?.userId) {
        res.setHeader("Cache-Control", "no-store");
    }
    next();
}

async function requireAdmin(req, res, next) {
    if (!req.session.userId) {
        return res.redirect("/signin");
    }

    if (req.session.userRole !== "admin") {
        try {
            await writeAuditLog({
                actorUserId: req.session.userId,
                actorRole: req.session.userRole,
                eventType: "admin.authorization.denied",
                req
            });
        } catch (error) {
            console.error("Audit logging failed.");
        }
        return res.status(403).send("Access denied. Admins only.");
    }

    next();
}

const fs = require("fs");
const databasePath = process.env.DATABASE_PATH || "./database/microloan.db";
if (isProduction && (!process.env.DATABASE_URL || !process.env.DATABASE_URL.trim())) throw new Error("DATABASE_URL must be configured in production; refusing SQLite fallback.");
const postgresDb = createPostgresDatabase();
const db = postgresDb ? null : (() => {
    fs.mkdirSync(path.dirname(databasePath), { recursive: true });
    return new Database(databasePath);
})();
const postgresReady = postgresDb ? postgresDb.initializeSchema() : Promise.resolve();
const repaymentRepository = createRepaymentRepository({ sqliteDb: db, postgres: postgresDb });
const dataRepository = createDataRepository({ sqliteDb: db, postgres: postgresDb, sessionSecret });
app.use(express.urlencoded({ extended: false, limit: MAX_REQUEST_BODY }));
app.use(securityHeaders);
app.use(requireRedisAvailability);
app.use(session({
    secret: sessionSecret,
    store: new RedisStore({
        client: redisClient,
        prefix: `${redisKeyPrefix}session:`,
        ttl: Math.floor(SESSION_MAX_AGE / 1000)
    }),
    resave: false,
    saveUninitialized: false,
    cookie: sessionCookieOptions
}));
app.use(ensureCsrfToken);
app.use(authenticatedCacheControl);
if (!postgresDb) db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'borrower',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
`);
if (!postgresDb) db.exec(`
    CREATE TABLE IF NOT EXISTS loans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        amount REAL NOT NULL,
        interest_rate REAL NOT NULL,
        interest_amount REAL NOT NULL,
        total_repayment REAL NOT NULL,
        purpose TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'Pending',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
`);
if (!postgresDb) db.exec(`
    CREATE TABLE IF NOT EXISTS repayments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        loan_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        amount REAL NOT NULL,
        payment_date DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (loan_id) REFERENCES loans(id),
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
`);
if (!postgresDb) db.exec(`
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
`);

async function writeAuditLog(options) {
    if (!AUDIT_EVENT_TYPES.has(options.eventType)) throw new Error("Unsupported audit event type.");
    return dataRepository.writeAuditLog(options);
}

async function transitionLoanStatus({ loanId, nextStatus, actorUserId, req }) {
    return dataRepository.transitionLoanStatus({
        loanId, nextStatus, actorUserId, req,
        eventType: nextStatus === "Approved" ? "admin.loan.approve" : "admin.loan.reject"
    });
}
app.get("/health/ready", async (req, res) => {
    let database = false;
    try { await postgresReady; if (postgresDb) await postgresDb.query("SELECT 1"); else db.prepare("SELECT 1").get(); database = true; } catch {}
    const redis = Boolean(redisClient.isReady);
    const ready = database && redis;
    res.status(ready ? 200 : 503).json({ ready, database, redis });
});

// Serve files from the public folder
app.use(express.static(path.join(__dirname, "public")));

// Home page
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "views", "index.html"));
});

// Sign Up page
app.get("/signup", (req, res) => {
    res.send(renderCsrfPage(path.join(__dirname, "views", "signup.html"), req));
});
// Sign In page
app.get("/signin", (req, res) => {
    res.send(renderCsrfPage(path.join(__dirname, "views", "signin.html"), req));
});
// Borrower Dashboard
app.get("/dashboard", async (req, res) => {
        if (!req.session.userId) {
        return res.redirect("/signin");
    }

    const loans = await dataRepository.listUserLoans(req.session.userId);
const repaymentSummary = await dataRepository.repaymentSummary(req.session.userId);

let repaymentSummaryText = "";

if (loans.length === 0) {

    repaymentSummaryText = "<p>No repayment records available.</p>";

} else {

    repaymentSummaryText = loans.map(loan => {

        const repaymentRecord = repaymentSummary.find(
            repayment => repayment.loan_id === loan.id
        );

        const totalRepaid = repaymentRecord
            ? repaymentRecord.total_repaid
            : 0;

        const totalRepayment = loan.total_repayment;

        const remainingBalance = nonNegative(
            new Decimal(totalRepayment).minus(totalRepaid).toString()
        );

        let repaymentStatus = "Unpaid";

        if (new Decimal(String(totalRepaid)).gt(0) && new Decimal(String(remainingBalance)).gt(0)) {
            repaymentStatus = "Partially Paid";
        }

        if (new Decimal(String(remainingBalance)).isZero() && new Decimal(String(totalRepaid)).gt(0)) {
            repaymentStatus = "Fully Paid";
        }

        return `
            <div>
                <h4>Loan #${escapeHtml(loan.id)}</h4>

                <p>Repayment Status:
                    <strong>${escapeHtml(repaymentStatus)}</strong>
                </p>

                <p>Total Repaid:
                    ₦${escapeHtml(formatNgn(totalRepaid))}
                </p>

                <p>Remaining Balance:
                    ₦${escapeHtml(formatNgn(remainingBalance))}
                </p>

                <hr>
            </div>
        `;

    }).join("");
}
let loanList = "";

    if (loans.length === 0) {
        loanList = "<p>You currently have no loan requests.</p>";
    } else {
        loanList = loans.map(loan => `
            <div>
                <h4>Loan #${escapeHtml(loan.id)}</h4>
                <p>Amount: ₦${escapeHtml(formatNgn(loan.amount))}</p>
                <p>Interest Rate: ${escapeHtml(loan.interest_rate)}%</p>
                <p>Interest: ₦${escapeHtml(formatNgn(loan.interest_amount))}</p>
                <p>Total Repayment: ₦${escapeHtml(formatNgn(loan.total_repayment))}</p>
                <p>Purpose: ${escapeHtml(loan.purpose)}</p>
                <p>Status: <strong>${escapeHtml(loan.status)}</strong></p>
                <hr>
            </div>
        `).join("");
    }

    let loanStatus = "";

if (loans.length === 0) {

    loanStatus = "<p>No active loans.</p>";

} else {

    const approvedLoans = loans.filter(
        loan => loan.status === "Approved"
    ).length;

    const pendingLoans = loans.filter(
        loan => loan.status === "Pending"
    ).length;

    const rejectedLoans = loans.filter(
        loan => loan.status === "Rejected"
    ).length;

    loanStatus = `
        <p>Approved Loans: <strong>${approvedLoans}</strong></p>
        <p>Pending Loans: <strong>${pendingLoans}</strong></p>
        <p>Rejected Loans: <strong>${rejectedLoans}</strong></p>
    `;
}

    const dashboardPath = path.join(__dirname, "views", "dashboard.html");

    let dashboard = require("fs").readFileSync(dashboardPath, "utf8");

    dashboard = dashboard.replace(
        "<p>You currently have no loan requests.</p>",
        loanList
    );

    dashboard = dashboard.replace(
        "<p>No active loan.</p>",
        loanStatus
    );
dashboard = dashboard.replace(
    "<p>No repayment records available.</p>",
    repaymentSummaryText
);
    dashboard = dashboard.replaceAll("<!-- CSRF_TOKEN -->", csrfInput(req));
    res.send(dashboard);
});

// Admin Dashboard
app.get("/admin-dashboard", requireAdmin, async (req, res) => {

    const loans = await dataRepository.adminLoans();
    const totalLoans = loans.length;

const approvedLoans = loans.filter(
    loan => loan.status === "Approved"
).length;

const pendingLoans = loans.filter(
    loan => loan.status === "Pending"
).length;

const rejectedLoans = loans.filter(
    loan => loan.status === "Rejected"
).length;

const totalLoanAmount = loans.reduce((total, loan) => new Decimal(total).plus(loan.amount), new Decimal(0)).toString();

const totalRepaid = await dataRepository.totalRepaid();

const totalRepaymentAmount = loans.reduce((total, loan) => new Decimal(total).plus(loan.total_repayment), new Decimal(0)).toString();

const outstandingBalance = nonNegative(new Decimal(totalRepaymentAmount).minus(totalRepaid).toString());

    let loanRequests = "";

    if (loans.length === 0) {

        loanRequests = "<p>No loan requests found.</p>";

    } else {

        loanRequests = loans.map(loan => `
            <div>
                <h3>Loan #${escapeHtml(loan.id)}</h3>

                <p>Borrower: ${escapeHtml(loan.borrower_name)}</p>

                <p>Email: ${escapeHtml(loan.borrower_email)}</p>

                <p>Amount: ₦${escapeHtml(formatNgn(loan.amount))}</p>

                <p>Interest Rate: ${escapeHtml(loan.interest_rate)}%</p>

                <p>Interest: ₦${escapeHtml(formatNgn(loan.interest_amount))}</p>

                <p>Total Repayment: ₦${escapeHtml(formatNgn(loan.total_repayment))}</p>

                <p>Purpose: ${escapeHtml(loan.purpose)}</p>

                <p>Status: <strong>${escapeHtml(loan.status)}</strong></p>

                ${loan.status === "Pending" ? `
                    <p>
                        <form action="/admin/approve-loan/${escapeHtml(loan.id)}" method="POST">
                            ${csrfInput(req)}
                            <button type="submit">Approve</button>
                        </form>

                        <form action="/admin/reject-loan/${escapeHtml(loan.id)}" method="POST">
                            ${csrfInput(req)}
                            <button type="submit">Reject</button>
                        </form>
                    </p>
                ` : ""}

                <hr>
            </div>
        `).join("");
    }

    const adminPath = path.join(
        __dirname,
        "views",
        "admin-dashboard.html"
    );

    let adminPage = require("fs").readFileSync(
        adminPath,
        "utf8"
    );
    adminPage = adminPage.replace(
    "<!-- LOAN OVERVIEW -->",
    `
    <p>Total Loans: <strong>${totalLoans}</strong></p>

    <p>Approved Loans: <strong>${approvedLoans}</strong></p>

    <p>Pending Loans: <strong>${pendingLoans}</strong></p>

    <p>Rejected Loans: <strong>${rejectedLoans}</strong></p>

    <p>Total Loan Amount: <strong>₦${escapeHtml(formatNgn(totalLoanAmount))}</strong></p>

    <p>Total Repaid: <strong>₦${escapeHtml(formatNgn(totalRepaid))}</strong></p>

    <p>Outstanding Balance: <strong>₦${escapeHtml(formatNgn(outstandingBalance))}</strong></p>
    `
);

    adminPage = adminPage.replace(
        /<div id="loan-requests">[\s\S]*?<\/div>/,
        `<div id="loan-requests">
            ${loanRequests}
        </div>`
    );
    adminPage = adminPage.replaceAll("<!-- CSRF_TOKEN -->", csrfInput(req));
     
    res.send(adminPage);
});


// Approve Loan
app.post("/admin/approve-loan/:id", requireAdmin, csrfProtection, async (req, res) => {
    const loanId = Number(req.params.id);
    if (!Number.isSafeInteger(loanId) || loanId <= 0) {
        return res.status(400).send("Invalid loan.");
    }
    try {
        if (!(await transitionLoanStatus({
            loanId,
            nextStatus: "Approved",
            actorUserId: req.session.userId,
            req
        }))) {
            return res.status(409).send("Loan is no longer pending or could not be found.");
        }
        res.redirect("/admin-dashboard");
    } catch (error) {
        console.error("Loan approval failed.");
        res.status(500).send("Could not approve loan.");
    }
});


// Reject Loan
app.post("/admin/reject-loan/:id", requireAdmin, csrfProtection, async (req, res) => {
    const loanId = Number(req.params.id);
    if (!Number.isSafeInteger(loanId) || loanId <= 0) {
        return res.status(400).send("Invalid loan.");
    }
    try {
        if (!(await transitionLoanStatus({
            loanId,
            nextStatus: "Rejected",
            actorUserId: req.session.userId,
            req
        }))) {
            return res.status(409).send("Loan is no longer pending or could not be found.");
        }
        res.redirect("/admin-dashboard");
    } catch (error) {
        console.error("Loan rejection failed.");
        res.status(500).send("Could not reject loan.");
    }
});

// My Loans page
app.get("/my-loans", async (req, res) => {
    if (!req.session.userId) {
        return res.redirect("/signin");
    }

    const loans = await dataRepository.listUserLoans(req.session.userId);

    const repaymentSummary = await dataRepository.repaymentSummary(req.session.userId);

    let loanList = "";

    if (loans.length === 0) {

        loanList = "<p>You have not submitted any loan requests yet.</p>";

    } else {

        loanList = loans.map(loan => {

            const repaymentRecord = repaymentSummary.find(
                repayment => repayment.loan_id === loan.id
            );

            const totalRepaid = repaymentRecord
                ? repaymentRecord.total_repaid
                : 0;

            const remainingBalance = nonNegative(new Decimal(loan.total_repayment).minus(totalRepaid).toString());

            let repaymentStatus = "Unpaid";

            if (new Decimal(String(totalRepaid)).gt(0) && new Decimal(String(remainingBalance)).gt(0)) {
                repaymentStatus = "Partially Paid";
            }

            if (new Decimal(String(remainingBalance)).isZero() && new Decimal(String(totalRepaid)).gt(0)) {
                repaymentStatus = "Fully Paid";
            }

            return `
                <div>
                    <h3>Loan #${escapeHtml(loan.id)}</h3>

                    <p>
                        Amount:
                        ₦${escapeHtml(formatNgn(loan.amount))}
                    </p>

                    <p>
                        Interest Rate:
                        ${escapeHtml(loan.interest_rate)}%
                    </p>

                    <p>
                        Interest:
                        ₦${escapeHtml(formatNgn(loan.interest_amount))}
                    </p>

                    <p>
                        Total Repayment:
                        ₦${escapeHtml(formatNgn(loan.total_repayment))}
                    </p>

                    <p>
                        Purpose:
                        ${escapeHtml(loan.purpose)}
                    </p>

                    <p>
                        Loan Status:
                        <strong>${escapeHtml(loan.status)}</strong>
                    </p>

                    <p>
                        Total Repaid:
                        ₦${escapeHtml(formatNgn(totalRepaid))}
                    </p>

                    <p>
                        Remaining Balance:
                        ₦${escapeHtml(formatNgn(remainingBalance))}
                    </p>

                    <p>
                        Repayment Status:
                        <strong>${escapeHtml(repaymentStatus)}</strong>
                    </p>

                    <hr>
                </div>
            `;

        }).join("");
    }

    const loansPath = path.join(
        __dirname,
        "views",
        "my-loans.html"
    );

    let loansPage = require("fs").readFileSync(
        loansPath,
        "utf8"
    );

    loansPage = loansPage.replace(
        "<p>Your loan information will appear here.</p>",
        loanList
    );
    loansPage = loansPage.replaceAll("<!-- CSRF_TOKEN -->", csrfInput(req));

    res.send(loansPage);
});
// Repayments page
app.get("/repayments", async (req, res) => {
        if (!req.session.userId) {
        return res.redirect("/signin");
    }

    const loans = await dataRepository.listUserLoans(req.session.userId);

    const repaymentRecords = await dataRepository.repaymentRecords(req.session.userId);

    let repaymentSummary = "";

    if (loans.length === 0) {

        repaymentSummary = "<p>You have no loans yet.</p>";

    } else {

        repaymentSummary = loans.map(loan => {

            const loanRepayments = repaymentRecords.filter(
                repayment => repayment.loan_id === loan.id
            );

            const totalRepaid = loanRepayments.reduce(
                (total, repayment) => new Decimal(total).plus(repayment.amount),
                new Decimal(0)
            ).toString();

            const remainingBalance = nonNegative(new Decimal(loan.total_repayment).minus(totalRepaid).toString());

            let repaymentStatus = "Unpaid";

            if (new Decimal(String(totalRepaid)).gt(0) && new Decimal(String(remainingBalance)).gt(0)) {
                repaymentStatus = "Partially Paid";
            }

            if (new Decimal(String(remainingBalance)).isZero() && new Decimal(String(totalRepaid)).gt(0)) {
                repaymentStatus = "Fully Paid";
            }

            let paymentList = "";

            if (loanRepayments.length === 0) {

                paymentList = "<p>No payments recorded for this loan.</p>";

            } else {

                paymentList = loanRepayments.map(repayment => `
                    <div>
                        <p>
                            <strong>Payment #${escapeHtml(repayment.id)}</strong>
                        </p>

                        <p>
                            Amount:
                            ₦${escapeHtml(formatNgn(repayment.amount))}
                        </p>

                        <p>
                            Payment Date:
                            ${escapeHtml(repayment.payment_date)}
                        </p>

                        <hr>
                    </div>
                `).join("");
            }

            return `
                <div>
                    <h3>Loan #${escapeHtml(loan.id)}</h3>

                    <p>
                        Loan Amount:
                        ₦${escapeHtml(formatNgn(loan.amount))}
                    </p>

                    <p>
                        Total Repayment:
                        ₦${escapeHtml(formatNgn(loan.total_repayment))}
                    </p>

                    <p>
                        Repayment Status:
                        <strong>${escapeHtml(repaymentStatus)}</strong>
                    </p>

                    <p>
                        Total Repaid:
                        ₦${escapeHtml(formatNgn(totalRepaid))}
                    </p>

                    <p>
                        Remaining Balance:
                        ₦${escapeHtml(formatNgn(remainingBalance))}
                    </p>

                    <h4>Payment Records</h4>

                    ${paymentList}

                    <hr>
                </div>
            `;

        }).join("");
    }

    const repaymentsPath = path.join(
        __dirname,
        "views",
        "repayments.html"
    );

    let repaymentsPage = require("fs").readFileSync(
        repaymentsPath,
        "utf8"
    );

    repaymentsPage = repaymentsPage.replace(
        "<p>Your repayment records will appear here.</p>",
        repaymentSummary
    );
    repaymentsPage = repaymentsPage.replaceAll("<!-- CSRF_TOKEN -->", csrfInput(req));

    res.send(repaymentsPage);
});
// Process Repayment
app.post("/repayments", csrfProtection, async (req, res) => {
    if (!req.session.userId) {
        return res.redirect("/signin");
    }

    const loanId = positiveInteger(req.body.loanId);
    const repaymentAmount = positiveNumericField(req.body.amount, MAX_REPAYMENT_AMOUNT);
    if (loanId === null || repaymentAmount === null) {
        return res.status(400).send("Please provide a valid repayment amount and loan ID.");
    }

    if (postgresDb) {
        try {
            await postgresReady;
            const result = await repaymentRepository.record({
                loanId,
                userId: req.session.userId,
                amount: repaymentAmount,
                idempotencyKey: req.get("Idempotency-Key") || req.body.idempotencyKey || null,
                req
            });
            if (result.reason === "not_found") return res.send("Loan not found.");
            if (result.reason === "idempotency_conflict") return res.status(409).send("Idempotency key was already used for a different repayment.");
            if (result.reason === "not_approved") return res.send(`This loan is not approved for repayment.<br><br>Loan Status: <strong>${escapeHtml(result.loan.status)}</strong><br><br><a href="/repayments">Back to Repayments</a>`);
            if (result.reason === "overpayment") return res.send(`Repayment amount is greater than the remaining balance.<br><br>Remaining balance: ₦${escapeHtml(formatNgn(result.remainingBalance))}<br><br><a href="/repayments">Back to Repayments</a>`);
            if (result.reason === "invalid_amount") return res.status(400).send("Please provide a valid repayment amount and loan ID.");
            const remaining = result.remainingBalance === null ? "already recorded" : formatNgn(result.remainingBalance);
            return res.send(`<h1>Repayment Recorded Successfully!</h1><p>Loan ID: ${escapeHtml(loanId)}</p><p>Repayment Amount: ₦${escapeHtml(formatNgn(repaymentAmount))}</p><p>Remaining Balance: ₦${escapeHtml(remaining)}</p><br><a href="/repayments">View Repayments</a><br><br><a href="/dashboard">Back to Dashboard</a>`);
        } catch (error) {
            console.error("PostgreSQL repayment failed.");
            return res.status(503).send("Database service is temporarily unavailable.");
        }
    }
    const loan = db.prepare(`
        SELECT *
        FROM loans
        WHERE id = ? AND user_id = ?
    `).get(loanId, req.session.userId);

    if (!loan) {
        return res.send("Loan not found.");
    }

    if (loan.status !== "Approved") {
    return res.send(`
        This loan is not approved for repayment.

        <br><br>

        Loan Status:
        <strong>${escapeHtml(loan.status)}</strong>

        <br><br>

        <a href="/repayments">Back to Repayments</a>
    `);
}

    const previousRepayments = db.prepare(`
        SELECT COALESCE(SUM(amount), 0) AS total_paid
        FROM repayments
        WHERE loan_id = ? AND user_id = ?
    `).get(loanId, req.session.userId);

    const remainingBalance = nonNegative(new Decimal(String(loan.total_repayment)).minus(String(previousRepayments.total_paid)).toString());

    if (new Decimal(String(repaymentAmount)).gt(remainingBalance)) {
        return res.send(`
            Repayment amount is greater than the remaining balance.

            <br><br>
            Remaining balance: ₦${escapeHtml(formatNgn(remainingBalance))}

            <br><br>
            <a href="/repayments">Back to Repayments</a>
        `);
    }

    try {
        const insertRepayment = db.prepare(`
            INSERT INTO repayments (
                loan_id,
                user_id,
                amount
            )
            VALUES (?, ?, ?)
        `);

        insertRepayment.run(
            loanId,
            req.session.userId,
            repaymentAmount
        );

        res.send(`
            <h1>Repayment Recorded Successfully!</h1>

            <p>Loan ID: ${escapeHtml(loanId)}</p>

            <p>Repayment Amount:
                ₦${escapeHtml(formatNgn(repaymentAmount))}
            </p>

            <p>Remaining Balance:
                ₦${escapeHtml(formatNgn(new Decimal(remainingBalance).minus(repaymentAmount).toString()))}
            </p>

            <br>

            <a href="/repayments">View Repayments</a>

            <br><br>

            <a href="/dashboard">Back to Dashboard</a>
        `);

    } catch (error) {
        console.error(error);
        res.send("Something went wrong while recording the repayment.");
    }
});
// Loan Request page
app.get("/request-loan", async (req, res) => {
    if (!req.session.userId) {
        return res.redirect("/signin");
    }

    res.send(renderCsrfPage(path.join(__dirname, "views", "request-loan.html"), req));
});
// Process Loan Request
app.post("/request-loan", csrfProtection, async (req, res) => {
    if (!req.session.userId) {
        return res.redirect("/signin");
    }

    const loanAmount = positiveNumericField(req.body.amount, MAX_LOAN_AMOUNT);
    const rate = numericField(req.body.interestRate, MAX_INTEREST_RATE);
    const cleanPurpose = boundedText(req.body.purpose, MAX_PURPOSE_LENGTH);
    if (loanAmount === null || rate === null || cleanPurpose === null) {
        return res.status(400).send("Please provide valid loan information.");
    }
    const interestAmount = new Decimal(loanAmount).times(rate).div(100).toString();
    const totalRepayment = new Decimal(loanAmount).plus(interestAmount).toString();

    try {
        await dataRepository.createLoan({ userId: req.session.userId, amount: loanAmount, rate, interestAmount, totalRepayment, purpose: cleanPurpose, req });

        res.send(`
            <h1>Loan Request Submitted Successfully!</h1>
            <p>Loan Amount: ₦${escapeHtml(formatNgn(loanAmount))}</p>
            <p>Interest: ₦${escapeHtml(formatNgn(interestAmount))}</p>
            <p>Total Repayment: ₦${escapeHtml(formatNgn(totalRepayment))}</p>
            <p>Status: Pending</p>
            <a href="/dashboard">Back to Dashboard</a>
        `);

    } catch (error) {
        console.error(error);
        res.send("Something went wrong while submitting your loan request.");
    }
});

// Process Sign In
app.post("/signin", csrfProtection, async (req, res) => {
    const email = normalizedEmail(req.body.email);
    const password = typeof req.body.password === "string" ? req.body.password : "";
    const rateLimitKey = loginAttemptKey(req, email);
    try {
        if (await isLoginRateLimited(rateLimitKey)) {
            return res.status(429).send("Too many sign-in attempts. Please try again later.");
        }

        const user = email && password.length <= MAX_PASSWORD_LENGTH
            ? await dataRepository.findUserByEmail(email)
            : null;

        if (!user) {
            const failureCount = await recordLoginFailure(rateLimitKey);
            if (failureCount === -1) {
                return res.status(429).send("Too many sign-in attempts. Please try again later.");
            }
            return res.send("Invalid email or password.");
        }

        const passwordMatch = bcrypt.compareSync(password, user.password);
        if (!passwordMatch) {
            if (user.role === "admin") {
                try {
                    await writeAuditLog({
                        actorUserId: user.id,
                        actorRole: "admin",
                        eventType: "admin.signin.failure",
                        req
                    });
                } catch (error) {
                    console.error("Audit logging failed.");
                }
            }
            const failureCount = await recordLoginFailure(rateLimitKey);
            if (failureCount === -1) {
                return res.status(429).send("Too many sign-in attempts. Please try again later.");
            }
            return res.send("Invalid email or password.");
        }

        await clearLoginFailures(rateLimitKey);

        req.session.regenerate(async (error) => {
            if (error) {
                console.error("Session regeneration failed.");
                return res.send("Could not sign in.");
            }

            req.session.userId = user.id;
            req.session.userName = user.name;
            req.session.userRole = user.role;
            req.session.csrfToken = createCsrfToken();

            if (user.role === "admin") {
                try {
                    await writeAuditLog({
                        actorUserId: user.id,
                        actorRole: "admin",
                        eventType: "admin.signin.success",
                        req
                    });
                } catch (auditError) {
                    console.error("Audit logging failed.");
                    return req.session.destroy(() => res.send("Could not sign in."));
                }
            }

            if (user.role === "admin") {
                res.redirect("/admin-dashboard");
            } else {
                res.redirect("/dashboard");
            }
        });
    } catch (error) {
        console.error("Shared login limiter unavailable.");
        return res.status(503).send("Sign-in is temporarily unavailable.");
    }
});
// Logout
app.post("/logout", csrfProtection, async (req, res) => {
    const auditContext = req.session.userRole === "admin"
        ? {
            actorUserId: req.session.userId,
            actorRole: "admin",
            eventType: "admin.logout",
            req
        }
        : null;
    if (auditContext) {
        try {
            await writeAuditLog(auditContext);
        } catch (error) {
            console.error("Audit logging failed.");
        }
    }
    req.session.destroy((error) => {
        if (error) {
            console.error("Session destruction failed.");
            return res.send("Could not log out.");
        }

        res.clearCookie("connect.sid", {
            httpOnly: sessionCookieOptions.httpOnly,
            secure: sessionCookieOptions.secure,
            sameSite: sessionCookieOptions.sameSite
        });
        res.redirect("/signin");
    });
});
// Process Sign Up
app.post("/signup", csrfProtection, async (req, res) => {
    const name = boundedText(req.body.name, MAX_NAME_LENGTH);
    const email = normalizedEmail(req.body.email);
    const password = typeof req.body.password === "string" ? req.body.password : "";
    const confirmPassword = typeof req.body.confirmPassword === "string"
        ? req.body.confirmPassword
        : "";

    if (!name || !email || password.length < 6 || password.length > MAX_PASSWORD_LENGTH) {
        return res.status(400).send("Please provide valid account information.");
    }
    if (password !== confirmPassword) {
        return res.status(400).send("Passwords do not match.");
    }

    const hashedPassword = bcrypt.hashSync(password, 10);

    try {
        await dataRepository.createUser({ name, email, password: hashedPassword });

        res.send("Account created successfully!");
    } catch (error) {
        if (error.code === "SQLITE_CONSTRAINT_UNIQUE" || error.code === "ACCOUNT_EXISTS" || error.code === "23505") {
            return res.send("An account with this email already exists.");
        }

        console.error(error);
        res.send("Something went wrong while creating the account.");
    }
});

app.use((error, req, res, next) => {
    if (error?.type === "entity.too.large" || error?.status === 413) {
        return res.status(413).send("Request is too large.");
    }
    console.error("Unhandled request error.");
    return res.status(500).send("Something went wrong while processing the request.");
});

// Start server when executed directly. Tests can import the app without binding a port.
if (require.main === module) {
    const shutdown = async () => {
        if (postgresDb) await postgresDb.close();
        await redisClient.quit().catch(() => {});
    };
    process.once("SIGTERM", shutdown);
    process.once("SIGINT", shutdown);
    Promise.all([redisReady, postgresReady]).then(() => {
        app.listen(PORT, "0.0.0.0", () => {
            console.log(`Micro-Loan Tracker running at http://localhost:${PORT}`);
        });
    }).catch(() => {
        console.error("Micro-Loan Tracker could not initialize its shared Redis store.");
        process.exitCode = 1;
    });
}

module.exports = {
    app,
    db,
    redisClient,
    redisReady,
    postgresDb,
    postgresReady,
    escapeHtml,
    isProduction,
    sessionCookieOptions,
    validateSessionSecret,
    securityHeaders,
    shouldUseHsts
};
