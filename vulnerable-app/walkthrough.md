# Vulnerable Backend Walkthrough

The backend provides a login API with intentional vulnerabilities and
detailed request logging. See [README](README.md) for the full endpoint
list and the SQL injection demo — this page is a login-specific
request/response transcript.

## Implemented Features

### 1. Postgres-backed user store

Seeded at startup by [backend/db.js](backend/db.js) into a real `users` table
(`id`, `email`, `password`, `role`) — not an in-memory mock. Passwords are
stored and compared as plain text, which is itself the intentional
vulnerability; there is no in-memory fallback.

```javascript
const seedUsers = [
  { email: 'admin@shopforge.com', password: 'admin123', role: 'administrator' },
  { email: 'jane@example.com', password: 'user123', role: 'user' },
  // ...
];
```

### 2. Detailed Request Logger

Located at [backend/middleware/logger.js](backend/middleware/logger.js), it logs the IP, headers, and body of every incoming request to the console.

### 3. Insecure Login API

Located at [backend/routes/auth.js](backend/routes/auth.js), the `POST /api/login` endpoint:

- **No hashing**: compares passwords as plain text, in the SQL query itself.
- **One error message for both cases**: a missing user and a wrong password
  both return the same `Invalid email or password`, on purpose — the
  distinguishing behavior an earlier version of this backend had is gone.
- **No rate limiting**: vulnerable to brute-force attacks, which is what
  makes it the target for `testing/signals/brute_force.sh` and
  `testing/jmeter/3A-Brute-force detection.jmx`.

## Verification Results

### Health Check

```bash
# Request
GET /api/health

# Response
{ "status": "up", "message": "Vulnerable backend is running" }
```

### Successful Login

```bash
# Request
POST /api/login
{ "email": "admin@shopforge.com", "password": "admin123" }

# Response
{
  "success": true,
  "message": "Login successful!",
  "user": { "id": 1, "email": "admin@shopforge.com", "role": "administrator" }
}
```

### Failed Login (wrong password, or no such user)

```bash
# Request
POST /api/login
{ "email": "admin@shopforge.com", "password": "wrongPassword" }

# Response (401)
{ "success": false, "message": "Invalid email or password" }
```

The request body field is `email`, not `username` — a request shaped with
`username` instead reads as `email: undefined`, matches no row, and gets the
same 401 above.

## How to Run

To start the backend server directly (outside Compose):

```bash
cd vulnerable-app/backend
npm install
npm start
```

The server listens on `http://localhost:5002` (`PORT` env var, default 5002 —
see [server.js](backend/server.js)), matching the port every other doc in
this repo uses for it. It expects a reachable Postgres; see
[README](README.md) for the Compose-based way to run it with one already
provisioned.
