require("dotenv").config();
const express = require("express");
const path = require("path");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const app = express();
const PORT = process.env.PORT || 3000;
function requireAdmin(req, res, next) {
    if (!req.session.userId) {
        return res.redirect("/signin");
    }

    if (req.session.userRole !== "admin") {
        return res.status(403).send("Access denied. Admins only.");
    }

    next();
}

const fs = require("fs");
fs.mkdirSync("./database", { recursive: true });

const db = new Database("./database/microloan.db");
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
}));
// Create Users table
db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'borrower',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
`);
// Create Loans table
db.exec(`
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
// Create Repayments table
db.exec(`
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
// Serve files from the public folder
app.use(express.static(path.join(__dirname, "public")));

// Home page
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "views", "index.html"));
});

// Sign Up page
app.get("/signup", (req, res) => {
    res.sendFile(path.join(__dirname, "views", "signup.html"));
});
// Sign In page
app.get("/signin", (req, res) => {
    res.sendFile(path.join(__dirname, "views", "signin.html"));
});
// Borrower Dashboard
app.get("/dashboard", (req, res) => {
        if (!req.session.userId) {
        return res.redirect("/signin");
    }

    const loans = db.prepare(`
        SELECT *
        FROM loans
        WHERE user_id = ?
        ORDER BY created_at DESC
    `).all(req.session.userId);
const repaymentSummary = db.prepare(`
    SELECT
        loan_id,
        COALESCE(SUM(amount), 0) AS total_repaid
    FROM repayments
    WHERE user_id = ?
    GROUP BY loan_id
`).all(req.session.userId);

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

        const remainingBalance = Math.max(
            totalRepayment - totalRepaid,
            0
        );

        let repaymentStatus = "Unpaid";

        if (totalRepaid > 0 && remainingBalance > 0) {
            repaymentStatus = "Partially Paid";
        }

        if (remainingBalance === 0 && totalRepaid > 0) {
            repaymentStatus = "Fully Paid";
        }

        return `
            <div>
                <h4>Loan #${loan.id}</h4>

                <p>Repayment Status:
                    <strong>${repaymentStatus}</strong>
                </p>

                <p>Total Repaid:
                    ₦${totalRepaid.toLocaleString()}
                </p>

                <p>Remaining Balance:
                    ₦${remainingBalance.toLocaleString()}
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
                <h4>Loan #${loan.id}</h4>
                <p>Amount: ₦${loan.amount.toLocaleString()}</p>
                <p>Interest Rate: ${loan.interest_rate}%</p>
                <p>Interest: ₦${loan.interest_amount.toLocaleString()}</p>
                <p>Total Repayment: ₦${loan.total_repayment.toLocaleString()}</p>
                <p>Purpose: ${loan.purpose}</p>
                <p>Status: <strong>${loan.status}</strong></p>
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

    res.send(dashboard);
});

// Admin Dashboard
app.get("/admin-dashboard", requireAdmin, (req, res) => {

    const loans = db.prepare(`
        SELECT
            loans.*,
            users.name AS borrower_name,
            users.email AS borrower_email
        FROM loans
        JOIN users ON loans.user_id = users.id
        ORDER BY loans.created_at DESC
    `).all();
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

const totalLoanAmount = loans.reduce(
    (total, loan) => total + loan.amount,
    0
);

const repaymentSummary = db.prepare(`
    SELECT COALESCE(SUM(amount), 0) AS total_repaid
    FROM repayments
`).get();

const totalRepaid = repaymentSummary.total_repaid;

const totalRepaymentAmount = loans.reduce(
    (total, loan) => total + loan.total_repayment,
    0
);

const outstandingBalance = Math.max(
    totalRepaymentAmount - totalRepaid,
    0
);

    let loanRequests = "";

    if (loans.length === 0) {

        loanRequests = "<p>No loan requests found.</p>";

    } else {

        loanRequests = loans.map(loan => `
            <div>
                <h3>Loan #${loan.id}</h3>

                <p>Borrower: ${loan.borrower_name}</p>

                <p>Email: ${loan.borrower_email}</p>

                <p>Amount: ₦${loan.amount.toLocaleString()}</p>

                <p>Interest Rate: ${loan.interest_rate}%</p>

                <p>Interest: ₦${loan.interest_amount.toLocaleString()}</p>

                <p>Total Repayment: ₦${loan.total_repayment.toLocaleString()}</p>

                <p>Purpose: ${loan.purpose}</p>

                <p>Status: <strong>${loan.status}</strong></p>

                ${loan.status === "Pending" ? `
                    <p>
                        <a href="/admin/approve-loan/${loan.id}">
                            <button type="button">Approve</button>
                        </a>

                        <a href="/admin/reject-loan/${loan.id}">
                            <button type="button">Reject</button>
                        </a>
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

    <p>Total Loan Amount: <strong>₦${totalLoanAmount.toLocaleString()}</strong></p>

    <p>Total Repaid: <strong>₦${totalRepaid.toLocaleString()}</strong></p>

    <p>Outstanding Balance: <strong>₦${outstandingBalance.toLocaleString()}</strong></p>
    `
);

    adminPage = adminPage.replace(
        /<div id="loan-requests">[\s\S]*?<\/div>/,
        `<div id="loan-requests">
            ${loanRequests}
        </div>`
    );
     
    res.send(adminPage);
});


// Approve Loan
app.get("/admin/approve-loan/:id", requireAdmin, (req, res) => {

    const loanId = Number(req.params.id);

    const loan = db.prepare(`
        SELECT *
        FROM loans
        WHERE id = ?
    `).get(loanId);

    if (!loan) {
        return res.send("Loan not found.");
    }

    db.prepare(`
        UPDATE loans
        SET status = 'Approved'
        WHERE id = ?
    `).run(loanId);

    res.redirect("/admin-dashboard");
});


// Reject Loan
app.get("/admin/reject-loan/:id", requireAdmin, (req, res) => {

    const loanId = Number(req.params.id);

    const loan = db.prepare(`
        SELECT *
        FROM loans
        WHERE id = ?
    `).get(loanId);

    if (!loan) {
        return res.send("Loan not found.");
    }

    db.prepare(`
        UPDATE loans
        SET status = 'Rejected'
        WHERE id = ?
    `).run(loanId);

    res.redirect("/admin-dashboard");
});

// My Loans page
app.get("/my-loans", (req, res) => {
    if (!req.session.userId) {
        return res.redirect("/signin");
    }

    const loans = db.prepare(`
        SELECT *
        FROM loans
        WHERE user_id = ?
        ORDER BY created_at DESC
    `).all(req.session.userId);

    const repaymentSummary = db.prepare(`
        SELECT
            loan_id,
            COALESCE(SUM(amount), 0) AS total_repaid
        FROM repayments
        WHERE user_id = ?
        GROUP BY loan_id
    `).all(req.session.userId);

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

            const remainingBalance = Math.max(
                loan.total_repayment - totalRepaid,
                0
            );

            let repaymentStatus = "Unpaid";

            if (totalRepaid > 0 && remainingBalance > 0) {
                repaymentStatus = "Partially Paid";
            }

            if (remainingBalance === 0 && totalRepaid > 0) {
                repaymentStatus = "Fully Paid";
            }

            return `
                <div>
                    <h3>Loan #${loan.id}</h3>

                    <p>
                        Amount:
                        ₦${loan.amount.toLocaleString()}
                    </p>

                    <p>
                        Interest Rate:
                        ${loan.interest_rate}%
                    </p>

                    <p>
                        Interest:
                        ₦${loan.interest_amount.toLocaleString()}
                    </p>

                    <p>
                        Total Repayment:
                        ₦${loan.total_repayment.toLocaleString()}
                    </p>

                    <p>
                        Purpose:
                        ${loan.purpose}
                    </p>

                    <p>
                        Loan Status:
                        <strong>${loan.status}</strong>
                    </p>

                    <p>
                        Total Repaid:
                        ₦${totalRepaid.toLocaleString()}
                    </p>

                    <p>
                        Remaining Balance:
                        ₦${remainingBalance.toLocaleString()}
                    </p>

                    <p>
                        Repayment Status:
                        <strong>${repaymentStatus}</strong>
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

    res.send(loansPage);
});
// Repayments page
app.get("/repayments", (req, res) => {
        if (!req.session.userId) {
        return res.redirect("/signin");
    }

    const loans = db.prepare(`
        SELECT *
        FROM loans
        WHERE user_id = ?
        ORDER BY created_at DESC
    `).all(req.session.userId);

    const repaymentRecords = db.prepare(`
        SELECT
            repayments.*,
            loans.amount AS loan_amount,
            loans.total_repayment
        FROM repayments
        JOIN loans ON repayments.loan_id = loans.id
        WHERE repayments.user_id = ?
        ORDER BY repayments.payment_date DESC
    `).all(req.session.userId);

    let repaymentSummary = "";

    if (loans.length === 0) {

        repaymentSummary = "<p>You have no loans yet.</p>";

    } else {

        repaymentSummary = loans.map(loan => {

            const loanRepayments = repaymentRecords.filter(
                repayment => repayment.loan_id === loan.id
            );

            const totalRepaid = loanRepayments.reduce(
                (total, repayment) => total + repayment.amount,
                0
            );

            const remainingBalance = Math.max(
                loan.total_repayment - totalRepaid,
                0
            );

            let repaymentStatus = "Unpaid";

            if (totalRepaid > 0 && remainingBalance > 0) {
                repaymentStatus = "Partially Paid";
            }

            if (remainingBalance === 0 && totalRepaid > 0) {
                repaymentStatus = "Fully Paid";
            }

            let paymentList = "";

            if (loanRepayments.length === 0) {

                paymentList = "<p>No payments recorded for this loan.</p>";

            } else {

                paymentList = loanRepayments.map(repayment => `
                    <div>
                        <p>
                            <strong>Payment #${repayment.id}</strong>
                        </p>

                        <p>
                            Amount:
                            ₦${repayment.amount.toLocaleString()}
                        </p>

                        <p>
                            Payment Date:
                            ${repayment.payment_date}
                        </p>

                        <hr>
                    </div>
                `).join("");
            }

            return `
                <div>
                    <h3>Loan #${loan.id}</h3>

                    <p>
                        Loan Amount:
                        ₦${loan.amount.toLocaleString()}
                    </p>

                    <p>
                        Total Repayment:
                        ₦${loan.total_repayment.toLocaleString()}
                    </p>

                    <p>
                        Repayment Status:
                        <strong>${repaymentStatus}</strong>
                    </p>

                    <p>
                        Total Repaid:
                        ₦${totalRepaid.toLocaleString()}
                    </p>

                    <p>
                        Remaining Balance:
                        ₦${remainingBalance.toLocaleString()}
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

    res.send(repaymentsPage);
});
// Process Repayment
app.post("/repayments", (req, res) => {
    if (!req.session.userId) {
        return res.redirect("/signin");
    }

    const { loanId, amount } = req.body;

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
        <strong>${loan.status}</strong>

        <br><br>

        <a href="/repayments">Back to Repayments</a>
    `);
}

    const repaymentAmount = Number(amount);

if (!Number.isFinite(repaymentAmount) || repaymentAmount <= 0) {
    return res.send("Please enter a valid repayment amount.");
}
    const previousRepayments = db.prepare(`
        SELECT COALESCE(SUM(amount), 0) AS total_paid
        FROM repayments
        WHERE loan_id = ? AND user_id = ?
    `).get(loanId, req.session.userId);

    const remainingBalance =
        loan.total_repayment - previousRepayments.total_paid;

    if (repaymentAmount > remainingBalance) {
        return res.send(`
            Repayment amount is greater than the remaining balance.

            <br><br>
            Remaining balance: ₦${remainingBalance.toLocaleString()}

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

            <p>Loan ID: ${loanId}</p>

            <p>Repayment Amount:
                ₦${repaymentAmount.toLocaleString()}
            </p>

            <p>Remaining Balance:
                ₦${(remainingBalance - repaymentAmount).toLocaleString()}
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
app.get("/request-loan", (req, res) => {
    if (!req.session.userId) {
        return res.redirect("/signin");
    }

    res.sendFile(path.join(__dirname, "views", "request-loan.html"));
});
// Process Loan Request
app.post("/request-loan", (req, res) => {
    if (!req.session.userId) {
        return res.redirect("/signin");
    }

    const { amount, interestRate, purpose } = req.body;

   const loanAmount = Number(amount);
const rate = Number(interestRate);
const cleanPurpose = purpose ? purpose.trim() : "";

if (
    !Number.isFinite(loanAmount) ||
    loanAmount <= 0 ||
    !Number.isFinite(rate) ||
    rate < 0 ||
    cleanPurpose.length === 0
) {
    return res.send("Please provide valid loan information.");
}
    const interestAmount = loanAmount * (rate / 100);
    const totalRepayment = loanAmount + interestAmount;

    try {
        const insertLoan = db.prepare(`
            INSERT INTO loans (
                user_id,
                amount,
                interest_rate,
                interest_amount,
                total_repayment,
                purpose
            )
            VALUES (?, ?, ?, ?, ?, ?)
        `);

        insertLoan.run(
            req.session.userId,
            loanAmount,
            rate,
            interestAmount,
           totalRepayment,
            cleanPurpose
        );

        res.send(`
            <h1>Loan Request Submitted Successfully!</h1>
            <p>Loan Amount: ₦${loanAmount.toLocaleString()}</p>
            <p>Interest: ₦${interestAmount.toLocaleString()}</p>
            <p>Total Repayment: ₦${totalRepayment.toLocaleString()}</p>
            <p>Status: Pending</p>
            <a href="/dashboard">Back to Dashboard</a>
        `);

    } catch (error) {
        console.error(error);
        res.send("Something went wrong while submitting your loan request.");
    }
});

// Process Sign In
app.post("/signin", (req, res) => {
    const { email, password } = req.body;

    const user = db.prepare(`
        SELECT * FROM users WHERE email = ?
    `).get(email);

    if (!user) {
        return res.send("Invalid email or password.");
    }

    const passwordMatch = bcrypt.compareSync(password, user.password);

    if (!passwordMatch) {
        return res.send("Invalid email or password.");
    }

    req.session.userId = user.id;
req.session.userName = user.name;
req.session.userRole = user.role;

if (user.role === "admin") {
    res.redirect("/admin-dashboard");
} else {
    res.redirect("/dashboard");
}
});
// Logout
app.get("/logout", (req, res) => {
    req.session.destroy((error) => {
        if (error) {
            console.error(error);
            return res.send("Could not log out.");
        }

        res.redirect("/signin");
    });
});
// Process Sign Up
app.post("/signup", (req, res) => {
    const { name, email, password, confirmPassword } = req.body;

    if (!name || !email || !password || !confirmPassword) {
    return res.send("Please fill in all required fields.");
}

if (password !== confirmPassword) {
    return res.send("Passwords do not match.");
}

if (password.length < 6) {
    return res.send("Password must be at least 6 characters long.");
}
    const hashedPassword = bcrypt.hashSync(password, 10);

    try {
        const insertUser = db.prepare(`
            INSERT INTO users (name, email, password)
            VALUES (?, ?, ?)
        `);

        insertUser.run(name, email, hashedPassword);

        res.send("Account created successfully!");
    } catch (error) {
        if (error.code === "SQLITE_CONSTRAINT_UNIQUE") {
            return res.send("An account with this email already exists.");
        }

        console.error(error);
        res.send("Something went wrong while creating the account.");
    }
});

// Start server
app.listen(PORT, "0.0.0.0", () => {
    console.log(`Micro-Loan Tracker running at http://localhost:${PORT}`);
});