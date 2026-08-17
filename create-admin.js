require("dotenv").config();

const fs = require("fs");
fs.mkdirSync("./database", { recursive: true });

const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");

const db = new Database("./database/microloan.db");

const name = "Micro-Loan Admin";
const email = process.env.ADMIN_EMAIL;
const password = process.env.ADMIN_PASSWORD;

if (!email || !password) {
    console.error("ADMIN_EMAIL or ADMIN_PASSWORD is missing.");
    process.exit(1);
}

try {
    // Create users table if it does not already exist
    db.prepare(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'borrower'
        )
    `).run();

    const hashedPassword = bcrypt.hashSync(password, 10);

    const existingAdmin = db.prepare(`
        SELECT id FROM users WHERE email = ?
    `).get(email);

    if (existingAdmin) {

        const updateAdmin = db.prepare(`
            UPDATE users
            SET name = ?, password = ?, role = ?
            WHERE email = ?
        `);

        updateAdmin.run(
            name,
            hashedPassword,
            "admin",
            email
        );

        console.log("Admin account updated successfully.");

    } else {

        const createAdmin = db.prepare(`
            INSERT INTO users (name, email, password, role)
            VALUES (?, ?, ?, ?)
        `);

        createAdmin.run(
            name,
            email,
            hashedPassword,
            "admin"
        );

        console.log("Admin account created successfully.");
    }

} catch (error) {
    console.error("Error creating admin:", error);
    process.exit(1);
} finally {
    db.close();
}