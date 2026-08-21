// Wipe every dashboard account so the next visit starts at /setup.
//
// Accounts live in Postgres, not in git, so a fresh database already starts
// clean -- this is only for a database that already has accounts in it.
//
//   npm run reset-accounts
//
// Uses the same IASG_POSTGRES_URL the app does, so it works whether Postgres
// is local or the Docker Compose container. Nothing else is touched: campaigns,
// feedback and policy all survive.

import { Pool } from "pg";

const url = process.env.IASG_POSTGRES_URL || process.env.DATABASE_URL;
if (!url) {
  console.error(
    "IASG_POSTGRES_URL is not set. Point it at the same database the dashboard uses, e.g.\n" +
      "  IASG_POSTGRES_URL=postgresql://iasg_user:changeme@localhost:5432/iasg npm run reset-accounts",
  );
  process.exit(1);
}

const pool = new Pool({ connectionString: url, connectionTimeoutMillis: 4000 });

try {
  // TRUNCATE is a no-op if the tables do not exist yet -- guard so a brand new
  // database (never migrated) reports "already clean" rather than an error.
  const { rows } = await pool.query(
    "SELECT to_regclass('public.users') AS users",
  );
  if (!rows[0].users) {
    console.log("No users table yet — this database already starts at /setup.");
  } else {
    const before = (await pool.query("SELECT count(*)::int AS n FROM users")).rows[0].n;
    await pool.query("TRUNCATE users, sessions");
    console.log(`Cleared ${before} account(s). The dashboard now starts at /setup.`);
  }
} catch (err) {
  console.error("Reset failed:", err.message);
  process.exit(1);
} finally {
  await pool.end();
}
