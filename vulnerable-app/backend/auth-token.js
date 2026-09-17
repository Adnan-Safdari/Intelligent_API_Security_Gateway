const crypto = require('node:crypto');

// Login tokens: HS256 JWTs signed with IASG_JWT_SECRET, which the gateway
// shares (identity.jwt in gateway/configs/config.yaml) so it can verify who is
// calling before it checks whose order came back.
//
// The fallback secret keeps `npm start` working on its own and matches the
// gateway's demo fallback. It is public, so anything real sets the variable.
const DEMO_SECRET = 'iasg-demo-jwt-secret-change-me';
const TOKEN_LIFETIME_SECONDS = 60 * 60;

const secret = () => process.env.IASG_JWT_SECRET || DEMO_SECRET;

const encode = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');

function sign(unsigned, key) {
  return crypto.createHmac('sha256', key).update(unsigned).digest('base64url');
}

function issueToken(user, { now = Date.now(), key = secret() } = {}) {
  const issuedAt = Math.floor(now / 1000);
  const unsigned = `${encode({ alg: 'HS256', typ: 'JWT' })}.${encode({
    sub: String(user.id),
    role: user.role,
    iat: issuedAt,
    exp: issuedAt + TOKEN_LIFETIME_SECONDS,
  })}`;
  return `${unsigned}.${sign(unsigned, key)}`;
}

// Returns the claims of a valid token, or null. The algorithm is fixed here and
// never read from the token, so "alg": "none" is just a bad signature.
function verifyToken(token, { now = Date.now(), key = secret() } = {}) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) return null;

  const expected = Buffer.from(sign(`${parts[0]}.${parts[1]}`, key));
  const given = Buffer.from(parts[2]);
  if (expected.length !== given.length || !crypto.timingSafeEqual(expected, given)) return null;

  try {
    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    const claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    if (header.alg !== 'HS256') return null;
    if (!Number.isInteger(claims.exp) || claims.exp * 1000 <= now) return null;
    return claims;
  } catch {
    return null;
  }
}

// The caller named by "Authorization: Bearer <jwt>", or null.
function callerFrom(req) {
  const match = /^Bearer\s+(\S+)$/.exec(req.get('authorization') || '');
  if (!match) return null;
  const claims = verifyToken(match[1]);
  if (!claims) return null;
  const id = Number(claims.sub);
  return Number.isInteger(id) && id > 0 ? { id, role: claims.role } : null;
}

module.exports = { issueToken, verifyToken, callerFrom, DEMO_SECRET };
