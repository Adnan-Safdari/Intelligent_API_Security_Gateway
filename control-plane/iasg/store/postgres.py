"""
Durable storage for what the agent has learned.

Redis is the transport and the hot path: the gateway reads policy:<ip> from it
on every request, and evidence arrives as a stream. Neither of those needs to
survive a restart -- a policy is meant to expire, and evidence that has been
correlated is done.

What does need to survive is the agent's memory: the campaigns it is tracking
and the corrections humans have made to it. Losing those turns an agent that
continues an investigation back into a script that starts over. That is what
this module keeps, and the reason policy keys are deliberately NOT here.

Entirely opt-in. With IASG_POSTGRES_URL unset -- or psycopg not installed, or
the server unreachable -- the control plane behaves exactly as it did before,
holding campaigns in Redis under a 24-hour TTL.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from iasg.models import Campaign

# Campaigns older than this stop being offered to the correlator. It matches
# the TTL the Redis-backed path used, so switching stores does not change which
# campaigns a cycle can merge into -- only whether they survive a restart.
# Rows stay in the table afterwards; this bounds the working set, not history.
WORKING_SET = timedelta(hours=24)

SCHEMA = """
CREATE TABLE IF NOT EXISTS campaigns (
    campaign_id   BIGINT PRIMARY KEY,
    type          TEXT        NOT NULL,
    confidence    REAL        NOT NULL,
    severity      TEXT        NOT NULL,
    status        TEXT        NOT NULL DEFAULT 'active',
    ips           TEXT[]      NOT NULL DEFAULT '{}',
    stages        TEXT[]      NOT NULL DEFAULT '{}',
    reason        TEXT        NOT NULL DEFAULT '',
    event_count   INTEGER     NOT NULL DEFAULT 0,
    quiet_cycles  INTEGER     NOT NULL DEFAULT 0,
    rotations     INTEGER     NOT NULL DEFAULT 0,
    persistence   INTEGER     NOT NULL DEFAULT 0,
    last_action   TEXT        NOT NULL DEFAULT '',
    outcome       TEXT        NOT NULL DEFAULT '',
    alerted       BOOLEAN     NOT NULL DEFAULT FALSE,
    explanation   TEXT        NOT NULL DEFAULT '',
    assessment    TEXT        NOT NULL DEFAULT '',
    signature     JSONB       NOT NULL DEFAULT '{}'::jsonb,
    first_seen    TIMESTAMPTZ NOT NULL,
    last_seen     TIMESTAMPTZ NOT NULL,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS campaigns_last_seen_idx ON campaigns (last_seen DESC);
CREATE INDEX IF NOT EXISTS campaigns_status_idx    ON campaigns (status);

-- One row per campaign type, not per correction: the agent only ever asks for
-- the net direction. See feedback/memory.py.
CREATE TABLE IF NOT EXISTS feedback (
    campaign_type TEXT PRIMARY KEY,
    up            INTEGER     NOT NULL DEFAULT 0,
    down          INTEGER     NOT NULL DEFAULT 0,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE SEQUENCE IF NOT EXISTS campaign_id_seq;
"""

# Column order shared by the reader and both writers, so they cannot drift.
COLUMNS = (
    "campaign_id", "type", "confidence", "severity", "status", "ips", "stages",
    "reason", "event_count", "quiet_cycles", "rotations", "persistence",
    "last_action", "outcome", "alerted", "explanation", "assessment",
    "signature", "first_seen", "last_seen",
)


class Database:
    """A live Postgres connection, plus the two things stored in it."""

    def __init__(self, dsn: str) -> None:
        import psycopg  # imported here so psycopg stays an optional extra

        # autocommit: every write here is a single statement, and a cycle that
        # crashes should leave behind what it had already decided.
        self._conn = psycopg.connect(dsn, autocommit=True, connect_timeout=5)
        with self._conn.cursor() as cur:
            cur.execute(SCHEMA)
            # Start the counter above whatever is already stored, so ids stay
            # unique across restarts and across a move from the Redis counter.
            cur.execute(
                "SELECT setval('campaign_id_seq',"
                " COALESCE((SELECT MAX(campaign_id) FROM campaigns), 0) + 1,"
                " false)"
            )

        self.campaigns = PostgresCampaigns(self._conn)
        self.feedback = PostgresFeedback(self._conn)

    def close(self) -> None:
        self._conn.close()


class PostgresCampaigns:
    """The three things CampaignRepository needs of a persistence layer."""

    def __init__(self, conn) -> None:
        self._conn = conn

    def all(self) -> list[Campaign]:
        """The working set: campaigns recent enough to still be merged into."""
        cutoff = datetime.now(timezone.utc) - WORKING_SET
        with self._conn.cursor() as cur:
            cur.execute(
                f"SELECT {', '.join(COLUMNS)} FROM campaigns"
                " WHERE last_seen >= %s ORDER BY last_seen DESC",
                (cutoff,),
            )
            return [_to_campaign(row) for row in cur.fetchall()]

    def history(self, limit: int = 200) -> list[Campaign]:
        """Everything ever recorded, newest first. For reporting, not deciding."""
        with self._conn.cursor() as cur:
            cur.execute(
                f"SELECT {', '.join(COLUMNS)} FROM campaigns"
                " ORDER BY last_seen DESC LIMIT %s",
                (limit,),
            )
            return [_to_campaign(row) for row in cur.fetchall()]

    def save(self, campaign: Campaign, ttl_seconds: int = 0) -> None:
        """
        Upsert. ttl_seconds is accepted and ignored -- the point of this store
        is that campaigns do not expire, and the caller should not have to know
        which store it got.
        """
        placeholders = ", ".join(["%s"] * len(COLUMNS))
        updates = ", ".join(
            f"{c} = EXCLUDED.{c}" for c in COLUMNS if c != "campaign_id"
        )
        with self._conn.cursor() as cur:
            cur.execute(
                f"INSERT INTO campaigns ({', '.join(COLUMNS)})"
                f" VALUES ({placeholders})"
                f" ON CONFLICT (campaign_id) DO UPDATE SET {updates},"
                " updated_at = now()",
                _to_row(campaign),
            )

    def next_id(self) -> str:
        with self._conn.cursor() as cur:
            cur.execute("SELECT nextval('campaign_id_seq')")
            return str(cur.fetchone()[0])


class PostgresFeedback:
    """What humans corrected, kept per campaign type."""

    def __init__(self, conn) -> None:
        self._conn = conn

    def tally(self, campaign_type: str) -> dict:
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT up, down FROM feedback WHERE campaign_type = %s",
                (campaign_type,),
            )
            row = cur.fetchone()
        return {"up": row[0], "down": row[1]} if row else {}

    def bump(self, campaign_type: str, direction: str) -> None:
        """Add one correction in `direction` ("up" or "down")."""
        if direction not in ("up", "down"):
            return
        with self._conn.cursor() as cur:
            cur.execute(
                f"INSERT INTO feedback (campaign_type, {direction})"
                " VALUES (%s, 1)"
                " ON CONFLICT (campaign_type) DO UPDATE"
                f" SET {direction} = feedback.{direction} + 1,"
                " updated_at = now()",
                (campaign_type,),
            )

    def all(self) -> dict[str, dict]:
        with self._conn.cursor() as cur:
            cur.execute("SELECT campaign_type, up, down FROM feedback")
            return {
                row[0]: {"up": row[1], "down": row[2]} for row in cur.fetchall()
            }


def open_database(settings) -> Database | None:
    """
    Connect, or return None and let the caller carry on with Redis.

    Durability is an upgrade, not a requirement. A missing driver or a database
    that is down must not stop the agent from defending anything.
    """
    if not settings.postgres_url:
        return None
    try:
        db = Database(settings.postgres_url)
    except ImportError:
        print(
            "[postgres] psycopg not installed; campaigns stay in Redis. "
            'Install with: pip install -e ".[postgres]"'
        )
        return None
    except Exception as err:  # noqa: BLE001 - any connection failure degrades
        print(f"[postgres] unavailable ({err}); campaigns stay in Redis")
        return None

    print("[postgres] campaigns and feedback are durable")
    return db


def _to_row(c: Campaign) -> tuple:
    return (
        int(c.campaign_id),
        c.type,
        float(c.confidence),
        c.severity,
        c.status,
        list(c.ips),
        list(c.stages),
        c.reason,
        int(c.event_count),
        int(c.quiet_cycles),
        int(c.rotations),
        int(c.persistence),
        c.last_action or "",
        c.outcome or "",
        bool(c.alerted),
        c.explanation or "",
        c.assessment or "",
        json.dumps(c.signature or {}),
        c.first_seen,
        c.last_seen,
    )


def _to_campaign(row: tuple) -> Campaign:
    signature = row[17]
    # psycopg returns jsonb already decoded; tolerate a string either way.
    if isinstance(signature, str):
        try:
            signature = json.loads(signature)
        except ValueError:
            signature = {}

    return Campaign(
        campaign_id=str(row[0]),
        type=row[1],
        confidence=float(row[2]),
        severity=row[3],
        status=row[4],
        ips=list(row[5] or []),
        stages=list(row[6] or []),
        reason=row[7],
        event_count=row[8],
        quiet_cycles=row[9],
        rotations=row[10],
        persistence=row[11],
        last_action=row[12],
        outcome=row[13],
        alerted=row[14],
        explanation=row[15],
        assessment=row[16],
        signature=signature or {},
        first_seen=_utc(row[18]),
        last_seen=_utc(row[19]),
    )


def _utc(value: datetime | None) -> datetime | None:
    """
    Postgres hands TIMESTAMPTZ back in the session's timezone, which is
    whatever the server was configured with. Everything else in the project
    works in UTC and formats times for display without converting, so a
    campaign loaded from here would otherwise print its start in local time
    and its end in UTC -- "between 11:55 and 06:27" for ninety seconds of
    attack. Comparisons were always correct; only the reading was wrong.
    """
    if value is None:
        return None
    return value.astimezone(timezone.utc)
