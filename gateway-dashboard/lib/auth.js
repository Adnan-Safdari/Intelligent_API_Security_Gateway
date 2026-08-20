import { cookies, headers } from "next/headers";
import {
  randomBytes,
  createHash,
  scrypt as scryptCb,
  timingSafeEqual,
} from "node:crypto";
import { promisify } from "node:util";
import { getPool } from "@/lib/postgres";
import { getRedis } from "@/lib/redis";

const scrypt = promisify(scryptCb);

export const SESSION_COOKIE = "iasg_session";
const SESSION_HOURS = 12;

// viewer < operator < admin. Anything that changes state names the lowest role
// allowed to do it, and the check is server-side without exception -- hiding a
// button is presentation, not authorisation.
export const ROLES = ["viewer", "operator", "admin"];

export function atLeast(role, required) {
  return ROLES.indexOf(role) >= ROLES.indexOf(required);
}

// scrypt from the standard library rather than a dependency. Parameters are
// stored alongside the hash so they can be raised later without invalidating
// everyone's password.
const SCRYPT = { N: 16384, r: 8, p: 1, keylen: 64 };

export async function hashPassword(password) {
  const salt = randomBytes(16);
  const key = await scrypt(password, salt, SCRYPT.keylen, {
    N: SCRYPT.N,
    r: SCRYPT.r,
    p: SCRYPT.p,
    maxmem: 64 * 1024 * 1024,
  });
  return [
    "scrypt",
    SCRYPT.N,
    SCRYPT.r,
    SCRYPT.p,
    salt.toString("base64"),
    key.toString("base64"),
  ].join("$");
}

export async function verifyPassword(password, stored) {
  try {
    const [scheme, N, r, p, salt, expected] = String(stored).split("$");
    if (scheme !== "scrypt") return false;

    const key = await scrypt(password, Buffer.from(salt, "base64"), 64, {
      N: Number(N),
      r: Number(r),
      p: Number(p),
      maxmem: 64 * 1024 * 1024,
    });
    const want = Buffer.from(expected, "base64");
    // Constant time: a length check first, because timingSafeEqual throws on
    // mismatched lengths and throwing is itself an observable difference.
    return key.length === want.length && timingSafeEqual(key, want);
  } catch {
    return false;
  }
}

const SCHEMA = `
  CREATE TABLE IF NOT EXISTS users (
    id            BIGSERIAL PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL CHECK (role IN ('admin','operator','viewer')),
    disabled      BOOLEAN NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at TIMESTAMPTZ
  );

  -- Only the hash of a session token is stored, so a database leak cannot be
  -- replayed as a live session.
  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id    BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    user_agent TEXT
  );
  CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions (user_id);
`;

let ready = null;

/**
 * The users database, or an error explaining why there isn't one.
 *
 * Authentication fails closed: with no durable store there is nowhere to keep
 * accounts, and a security console that silently runs unauthenticated is worse
 * than one that refuses to start.
 */
export async function db() {
  const pool = getPool();
  if (!pool) {
    throw new Error(
      "authentication needs Postgres — set IASG_POSTGRES_URL and restart",
    );
  }
  ready ??= pool.query(SCHEMA);
  await ready;
  return pool;
}

export async function userCount() {
  const pool = await db();
  const { rows } = await pool.query("SELECT count(*)::int AS n FROM users");
  return rows[0].n;
}

export async function createUser({ username, password, role }) {
  const name = String(username || "").trim().toLowerCase();
  if (!/^[a-z0-9._-]{3,32}$/.test(name)) {
    throw new Error("username must be 3-32 characters: a-z 0-9 . _ -");
  }
  if (String(password || "").length < 10) {
    throw new Error("password must be at least 10 characters");
  }
  if (!ROLES.includes(role)) throw new Error("unknown role");

  const pool = await db();
  const hash = await hashPassword(password);
  try {
    const { rows } = await pool.query(
      `INSERT INTO users (username, password_hash, role)
       VALUES ($1, $2, $3)
       RETURNING id, username, role, disabled, created_at, last_login_at`,
      [name, hash, role],
    );
    return rows[0];
  } catch (err) {
    if (err.code === "23505") throw new Error("that username is taken");
    throw err;
  }
}

// The console detects brute force for a living; leaving its own login
// unthrottled would be difficult to explain. Redis because it is already here
// and the counter is meant to expire.
const MAX_ATTEMPTS = 10;
const LOCKOUT_SECONDS = 900;

async function attempts(name, bump) {
  try {
    const redis = await getRedis();
    const key = `iasg:login_fail:${name}`;
    if (!bump) return Number((await redis.get(key)) || 0);
    const n = await redis.incr(key);
    if (n === 1) await redis.expire(key, LOCKOUT_SECONDS);
    return n;
  } catch {
    // Redis down must not lock everyone out of the console.
    return 0;
  }
}

async function clearAttempts(name) {
  try {
    const redis = await getRedis();
    await redis.del(`iasg:login_fail:${name}`);
  } catch {
    /* nothing to clear */
  }
}

export async function login(username, password, userAgent) {
  const name = String(username || "").trim().toLowerCase();

  if ((await attempts(name)) >= MAX_ATTEMPTS) {
    return { ok: false, error: "too many attempts — try again in 15 minutes" };
  }

  const pool = await db();
  const { rows } = await pool.query(
    "SELECT id, username, password_hash, role, disabled FROM users WHERE username = $1",
    [name],
  );
  const user = rows[0];

  // Hash even when the user does not exist, so "no such user" and "wrong
  // password" take the same time and cannot be told apart.
  const valid = user
    ? await verifyPassword(password, user.password_hash)
    : await verifyPassword(password, await hashPassword("decoy-comparison"));

  if (!user || !valid || user.disabled) {
    await attempts(name, true);
    // One message for every failure: which half was wrong is not the
    // attacker's business.
    return { ok: false, error: "invalid username or password" };
  }

  await clearAttempts(name);

  const token = randomBytes(32).toString("base64url");
  const expires = new Date(Date.now() + SESSION_HOURS * 3600_000);
  await pool.query(
    `INSERT INTO sessions (token_hash, user_id, expires_at, user_agent)
     VALUES ($1, $2, $3, $4)`,
    [sha256(token), user.id, expires, String(userAgent || "").slice(0, 200)],
  );
  await pool.query("UPDATE users SET last_login_at = now() WHERE id = $1", [
    user.id,
  ]);

  return {
    ok: true,
    token,
    expires,
    user: { id: String(user.id), username: user.username, role: user.role },
  };
}

export function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

export function cookieOptions(expires) {
  return {
    httpOnly: true,
    sameSite: "lax",
    path: "/",
    // Set when served over TLS. Left off for http://localhost, or the browser
    // would silently drop the cookie and login would appear to do nothing.
    secure: process.env.NODE_ENV === "production",
    expires,
  };
}

/** The signed-in user, or null. Never throws for an anonymous visitor. */
export async function currentUser() {
  let token;
  try {
    token = (await cookies()).get(SESSION_COOKIE)?.value;
  } catch {
    return null;
  }
  if (!token) return null;

  try {
    const pool = await db();
    const { rows } = await pool.query(
      `SELECT u.id, u.username, u.role, u.disabled, s.expires_at
         FROM sessions s
         JOIN users u ON u.id = s.user_id
        WHERE s.token_hash = $1`,
      [sha256(token)],
    );
    const row = rows[0];
    if (!row || row.disabled) return null;
    if (new Date(row.expires_at) < new Date()) {
      await pool.query("DELETE FROM sessions WHERE token_hash = $1", [
        sha256(token),
      ]);
      return null;
    }
    return { id: String(row.id), username: row.username, role: row.role };
  } catch {
    return null;
  }
}

export async function destroySession() {
  try {
    const jar = await cookies();
    const token = jar.get(SESSION_COOKIE)?.value;
    if (token) {
      const pool = await db();
      await pool.query("DELETE FROM sessions WHERE token_hash = $1", [
        sha256(token),
      ]);
    }
  } catch {
    /* the cookie is cleared regardless */
  }
}

/**
 * Gate for route handlers. Returns the user, or a Response to return as-is.
 *
 *   const gate = await require("operator");
 *   if (gate.denied) return gate.denied;
 */
export async function require(role) {
  const user = await currentUser();
  if (!user) {
    return {
      denied: Response.json({ ok: false, error: "not signed in" }, { status: 401 }),
    };
  }
  if (!atLeast(user.role, role)) {
    return {
      denied: Response.json(
        { ok: false, error: `requires the ${role} role` },
        { status: 403 },
      ),
    };
  }
  return { user };
}

export async function userAgent() {
  try {
    return (await headers()).get("user-agent") || "";
  } catch {
    return "";
  }
}
