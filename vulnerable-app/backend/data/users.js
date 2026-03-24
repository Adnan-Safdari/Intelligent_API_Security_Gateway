/**
 * Mock User Database
 * 
 * This is a simple in-memory array to store user credentials.
 * Intentionally insecure:
 * - No password hashing (plain text passwords)
 * - Hardcoded admin and test accounts
 */

const users = [
  {
    id: 1,
    username: "admin",
    password: "adminPassword123", // VERY INSECURE: Plain text password
    role: "administrator"
  },
  {
    id: 2,
    username: "user1",
    password: "password1",
    role: "user"
  },
  {
    id: 3,
    username: "john_doe",
    password: "doePassword",
    role: "user"
  }
];

module.exports = users;
