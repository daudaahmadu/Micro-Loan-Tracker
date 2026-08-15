# Micro-Loan Tracker

## Project Overview

Micro-Loan Tracker is a web-based loan management system designed to help borrowers request and monitor micro-loans and track their repayments, while administrators manage loan requests and monitor overall loan activity.

## Project Objectives

The system is designed to:

- Allow borrowers to create accounts and securely sign in.
- Allow borrowers to submit micro-loan requests.
- Calculate loan interest and total repayment amounts.
- Allow administrators to review loan requests.
- Allow administrators to approve or reject loan requests.
- Allow borrowers to monitor their loan status.
- Record and track loan repayments.
- Calculate remaining loan balances.
- Prevent unauthorized repayments.
- Provide administrators with an overview of loan activity.

## Main Features

### Borrower

- Account registration
- Secure sign in and logout
- Loan request submission
- Loan status tracking
- My Loans page
- Repayment recording
- Repayment history
- Remaining balance tracking

### Administrator

- Secure administrator access
- View loan requests
- Approve loan requests
- Reject loan requests
- View loan statistics
- Monitor total loans
- Monitor total repayments
- Monitor outstanding balances

## Security Features

The system includes:

- Session-based authentication
- Role-based authorization
- Password hashing using bcrypt
- Borrower loan ownership checks
- Input validation
- Approved-loan repayment restrictions
- Pending and rejected loan repayment protection
- Overpayment protection
- Environment-based session secret
- `.env` protection through `.gitignore`

## Technology Stack

- HTML5
- CSS3
- JavaScript
- Node.js
- Express.js
- SQLite
- better-sqlite3
- bcrypt
- express-session
- dotenv

## Project Structure

```text
Micro-Loan-Tracker/
├── server.js
├── package.json
├── package-lock.json
├── create-admin.js
├── .gitignore
├── public/
│   └── style.css
└── views/
    ├── index.html
    ├── signup.html
    ├── signin.html
    ├── request-loan.html
    ├── dashboard.html
    ├── my-loans.html
    ├── repayments.html
    └── admin-dashboard.html