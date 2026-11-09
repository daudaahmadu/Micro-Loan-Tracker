const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const { once } = require("node:events");
const bcrypt = require("bcryptjs");

const enabled = Boolean(process.env.DATABASE_URL);
if (enabled) {
    process.env.NODE_ENV ||= "test";
    process.env.SESSION_SECRET ||= "postgres-workflow-test-session-secret-long-enough";
    process.env.REDIS_URL ||= "redis://127.0.0.1:6380/15";
    process.env.REDIS_KEY_PREFIX ||= `mlt:test:postgres-workflow:${process.pid}:`;
}

const { app, postgresDb, postgresReady, redisClient, redisReady } = enabled
    ? require("../server")
    : {};

let server;
let baseUrl;

function body(values) {
    return new URLSearchParams(values).toString();
}

function cookieFrom(response) {
    return response.headers.get("set-cookie")?.split(";", 1)[0];
}

function tokenFrom(text) {
    const match = text.match(/name="_csrf" value="([a-f0-9]{64})"/);
    assert.ok(match, "expected a CSRF token");
    return match[1];
}

async function request(pathname, options = {}) {
    const response = await fetch(`${baseUrl}${pathname}`, {
        redirect: "manual",
        ...options,
        headers: {
            ...(options.body ? { "content-type": "application/x-www-form-urlencoded" } : {}),
            ...(options.headers || {})
        }
    });
    return { response, text: await response.text() };
}

async function pageToken(pathname, cookie) {
    const result = await request(pathname, { headers: cookie ? { cookie } : undefined });
    return {
        cookie: cookieFrom(result.response) || cookie,
        token: tokenFrom(result.text),
        text: result.text
    };
}

async function login(email, password) {
    const page = await pageToken("/signin");
    const result = await request("/signin", {
        method: "POST",
        headers: { cookie: page.cookie },
        body: body({ email, password, _csrf: page.token })
    });
    assert.equal(result.response.status, 302);
    return cookieFrom(result.response);
}

test.before(async () => {
    if (!enabled) return;
    await Promise.all([postgresReady, redisReady]);
    const suffix = `${Date.now()}-${process.pid}`;
    const adminEmail = `workflow-admin-${suffix}@example.test`;
    await postgresDb.query(
        "INSERT INTO users (name,email,password,role) VALUES ($1,$2,$3,'admin')",
        ["Workflow Administrator", adminEmail, bcrypt.hashSync("Admin-Workflow-123!", 10)]
    );
    process.env.WORKFLOW_ADMIN_EMAIL = adminEmail;
    server = http.createServer(app);
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    baseUrl = `http://127.0.0.1:${server.address().port}`;
});

test.after(async () => {
    if (!enabled) return;
    server.close();
    await once(server, "close");
    await postgresDb.close();
    await redisClient.quit();
});

test("PostgreSQL borrower and administrator HTTP workflows preserve financial and audit behavior", { skip: !enabled }, async () => {
    const suffix = `${Date.now()}-${process.pid}`;
    const borrowerEmail = `workflow-borrower-${suffix}@example.test`;
    const borrowerPassword = "Borrower-Workflow-123!";
    const adminEmail = process.env.WORKFLOW_ADMIN_EMAIL;

    const signupPage = await pageToken("/signup");
    const signup = await request("/signup", {
        method: "POST",
        headers: { cookie: signupPage.cookie },
        body: body({
            name: "PostgreSQL Borrower",
            email: borrowerEmail,
            password: borrowerPassword,
            confirmPassword: borrowerPassword,
            _csrf: signupPage.token
        })
    });
    assert.equal(signup.response.status, 200);
    assert.match(signup.text, /Account created successfully/);

    const borrowerCookie = await login(borrowerEmail, borrowerPassword);
    const borrowerDashboard = await pageToken("/dashboard", borrowerCookie);
    const loanRequest = await request("/request-loan", {
        method: "POST",
        headers: { cookie: borrowerCookie },
        body: body({ amount: "100", interestRate: "5", purpose: "Synthetic working capital", _csrf: borrowerDashboard.token })
    });
    assert.equal(loanRequest.response.status, 200);

    const loan = await postgresDb.query("SELECT id FROM loans WHERE user_id = (SELECT id FROM users WHERE email = $1) ORDER BY id DESC LIMIT 1", [borrowerEmail]);
    const loanId = loan.rows[0].id;
    const adminCookie = await login(adminEmail, "Admin-Workflow-123!");
    const adminPage = await pageToken("/admin-dashboard", adminCookie);
    const approval = await request(`/admin/approve-loan/${loanId}`, {
        method: "POST",
        headers: { cookie: adminCookie },
        body: body({ _csrf: adminPage.token })
    });
    assert.equal(approval.response.status, 302);

    const repaymentPage = await pageToken("/repayments", borrowerCookie);
    const repayment = await request("/repayments", {
        method: "POST",
        headers: { cookie: borrowerCookie, "Idempotency-Key": `workflow-${suffix}` },
        body: body({ loanId, amount: "10", _csrf: repaymentPage.token })
    });
    assert.equal(repayment.response.status, 200);
    assert.match(repayment.text, /Repayment Recorded Successfully/);

    const history = await request("/repayments", { headers: { cookie: borrowerCookie } });
    assert.equal(history.response.status, 200);
    assert.match(history.text, /10/);

    const dashboard = await request("/dashboard", { headers: { cookie: borrowerCookie } });
    assert.equal(dashboard.response.status, 200);
    assert.match(dashboard.text, /Partially Paid|Unpaid|Fully Paid/);

    const rejectionLoan = await postgresDb.query(
        "INSERT INTO loans (user_id,amount,interest_rate,interest_amount,total_repayment,purpose) VALUES ((SELECT id FROM users WHERE email=$1),100,5,5,105,'Synthetic rejection') RETURNING id",
        [borrowerEmail]
    );
    const adminPageAgain = await pageToken("/admin-dashboard", adminCookie);
    const rejection = await request(`/admin/reject-loan/${rejectionLoan.rows[0].id}`, {
        method: "POST",
        headers: { cookie: adminCookie },
        body: body({ _csrf: adminPageAgain.token })
    });
    assert.equal(rejection.response.status, 302);

    const audit = await postgresDb.query(
        "SELECT event_type FROM audit_logs WHERE target_type='loan' AND target_id=$1 ORDER BY id",
        [loanId]
    );
    assert.deepEqual(audit.rows.map(row => row.event_type), ["admin.loan.approve"]);

    const logoutPage = await pageToken("/dashboard", borrowerCookie);
    const logout = await request("/logout", {
        method: "POST",
        headers: { cookie: borrowerCookie },
        body: body({ _csrf: logoutPage.token })
    });
    assert.equal(logout.response.status, 302);
    assert.equal(logout.response.headers.get("location"), "/signin");
});
