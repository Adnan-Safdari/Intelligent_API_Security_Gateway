# Vulnerable Backend Walkthrough

The backend is now ready for security testing. It provides a simple login API with intentional vulnerabilities and detailed request logging.

## Implemented Features

### 1. In-Memory Mock Database
Located at [backend/data/users.js](file:///d:/College/Capstone/Intelligent_API_Security_Gateway/vulnerable-app/backend/data/users.js), it contains a list of test users with plain text passwords.

```javascript
const users = [
  { id: 1, username: "admin", password: "adminPassword123", role: "administrator" },
  // ...
];
```

### 2. Detailed Request Logger
Located at [backend/middleware/logger.js](file:///d:/College/Capstone/Intelligent_API_Security_Gateway/vulnerable-app/backend/middleware/logger.js), it logs the IP, Headers, and Body of every incoming request to the console.

### 3. Insecure Login API
Located at [backend/routes/auth.js](file:///d:/College/Capstone/Intelligent_API_Security_Gateway/vulnerable-app/backend/routes/auth.js), the `POST /api/login` endpoint:
- **No Hashing**: Compares passwords as plain text.
- **Verbose Errors**: Informs the user if the "User was not found" or the "Password was incorrect".
- **No Rate Limiting**: Vulnerable to brute-force attacks.

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
{ "username": "admin", "password": "adminPassword123" }

# Response
{
  "success": true,
  "message": "Login successful!",
  "user": { "id": 1, "username": "admin", "role": "administrator" }
}
```

### Failed Login (Incorrect Password)
```bash
# Request
POST /api/login
{ "username": "admin", "password": "wrongPassword" }

# Response
{ "success": false, "message": "Incorrect password" }
```

## How to Run
To start the backend server:
```bash
cd backend
npm start
```
The server will run on `http://localhost:5000`.
