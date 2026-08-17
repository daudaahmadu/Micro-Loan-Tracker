require("dotenv").config();

const fs = require("fs");
fs.mkdirSync("./database", { recursive: true });

const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const db = new Database("./database/microloan.db");

const name = "Micro-Loan Admin";
const email = process.env.ADMIN_EMAIL;
const password = process.env.ADMIN_PASSWORD;
const hashedPassword = bcrypt.hashSync(password, 10);

try {
    const existingAdmin = db.prepare(`
        SELECT id FROM users WHERE email = ?
    `).get(email);

    if (existingAdmin) {
        console.log("Admin account already exists.");
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
} finally {
    db.close();
}