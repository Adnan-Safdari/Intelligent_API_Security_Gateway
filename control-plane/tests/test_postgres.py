"""
The durable path, exercised against a real Postgres.

Skipped unless IASG_TEST_POSTGRES_URL points at a database the test may write
to -- these tests create and truncate tables, so they must never be aimed at
anything that matters. Everything else in the suite runs without a database,
which is the point of the store abstraction.

    createdb iasg_test
    IASG_TEST_POSTGRES_URL=postgresql://iasg_user:changeme@localhost:5432/iasg_test \
        .venv/bin/python -m pytest tests/test_postgres.py
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone

import pytest

from iasg.campaigns.repository import CampaignRepository
from iasg.config import Settings
from iasg.feedback.memory import FeedbackMemory
from iasg.models import Campaign
from iasg.store.memory import MemoryStore

DSN = os.getenv("IASG_TEST_POSTGRES_URL")

pytestmark = pytest.mark.skipif(
    not DSN, reason="set IASG_TEST_POSTGRES_URL to run the Postgres tests"
)


@pytest.fixture
def db():
    from iasg.store.postgres import Database

    database = Database(DSN)
    with database._conn.cursor() as cur:
        cur.execute("TRUNCATE campaigns, feedback")
        cur.execute("SELECT setval('campaign_id_seq', 1, false)")
    yield database
    database.close()


def _campaign(**kw) -> Campaign:
    now = datetime.now(timezone.utc)
    fields = dict(
        campaign_id="1",
        type="Credential Stuffing",
        confidence=0.9,
        ips=["203.0.113.5", "203.0.113.9"],
        reason="2 IPs sharing same endpoint",
        severity="high",
        first_seen=now - timedelta(minutes=5),
        last_seen=now,
        event_count=20,
        signature={"endpoint": "/api/login", "user_agent": "curl/8.4.0"},
    )
    fields.update(kw)
    return Campaign(**fields)


def test_a_campaign_survives_being_written_and_read_back(db):
    db.campaigns.save(_campaign())
    (loaded,) = db.campaigns.all()

    assert loaded.campaign_id == "1"
    assert loaded.type == "Credential Stuffing"
    assert loaded.ips == ["203.0.113.5", "203.0.113.9"]
    assert loaded.signature["endpoint"] == "/api/login"


def test_timestamps_come_back_in_utc(db):
    """
    Postgres returns TIMESTAMPTZ in the session's zone. The rest of the project
    formats times without converting, so a campaign whose start printed as
    local and end as UTC read as ending before it began.
    """
    db.campaigns.save(_campaign())
    (loaded,) = db.campaigns.all()

    assert loaded.first_seen.utcoffset() == timedelta(0)
    assert loaded.last_seen.utcoffset() == timedelta(0)
    assert loaded.first_seen <= loaded.last_seen


def test_saving_the_same_campaign_twice_updates_rather_than_duplicates(db):
    db.campaigns.save(_campaign())
    db.campaigns.save(_campaign(event_count=99, status="contained"))

    campaigns = db.campaigns.all()
    assert len(campaigns) == 1
    assert campaigns[0].event_count == 99
    assert campaigns[0].status == "contained"


def test_ids_keep_climbing_across_reconnects(db):
    first = db.campaigns.next_id()
    db.campaigns.save(_campaign(campaign_id=first))

    from iasg.store.postgres import Database

    reconnected = Database(DSN)
    try:
        assert int(reconnected.campaigns.next_id()) > int(first)
    finally:
        reconnected.close()


def test_campaigns_outside_the_working_set_are_not_offered_to_the_correlator(db):
    old = datetime.now(timezone.utc) - timedelta(hours=30)
    db.campaigns.save(_campaign(first_seen=old, last_seen=old))

    # Gone from the working set, but never deleted -- history is the reason
    # this store exists.
    assert db.campaigns.all() == []
    assert len(db.campaigns.history()) == 1


def test_the_repository_uses_the_database_when_given_one(db):
    repo = CampaignRepository(MemoryStore(), persistence=db.campaigns)
    repo.save(_campaign())

    # Straight out of Postgres, with nothing in the key-value store.
    (loaded,) = repo.all()
    assert loaded.campaign_id == "1"


def test_a_wiped_key_value_store_does_not_lose_the_investigation(db):
    """The whole point: Redis restarting must not restart the investigation."""
    store = MemoryStore()
    repo = CampaignRepository(store, persistence=db.campaigns)
    fresh = _campaign(campaign_id=repo._next_id())
    repo.save(fresh)

    # The restart.
    wiped = MemoryStore()
    after = CampaignRepository(wiped, persistence=db.campaigns)

    (survivor,) = after.all()
    assert survivor.campaign_id == fresh.campaign_id
    assert survivor.event_count == 20


def test_corrections_accumulate_in_the_database(db):
    memory = FeedbackMemory(MemoryStore(), Settings(), persistence=db.feedback)

    memory.record("Brute Force", "throttle", "temp_block")
    memory.record("Brute Force", "throttle", "temp_block")

    assert memory.bias_for("Brute Force") == 1
    assert db.feedback.all()["Brute Force"] == {"up": 2, "down": 0}


def test_opposite_corrections_cancel(db):
    memory = FeedbackMemory(MemoryStore(), Settings(), persistence=db.feedback)

    memory.record("Reconnaissance", "throttle", "temp_block")
    memory.record("Reconnaissance", "temp_block", "throttle")

    assert memory.bias_for("Reconnaissance") == 0


def test_campaigns_reach_the_key_value_store_too(db):
    """
    Postgres is the record; Redis stays the read path.

    The dashboard, like the gateway, reads Redis. When campaigns moved to
    Postgres they stopped being written there at all, and the console's
    campaign and feedback panels silently went blank while policy kept
    working -- the failure looked like "no attacks" rather than an outage.
    """
    store = MemoryStore()
    repo = CampaignRepository(store, persistence=db.campaigns)
    repo.save(_campaign())

    assert store.get("campaign:1"), "campaign missing from the read path"
    assert db.campaigns.all(), "campaign missing from the record"


def test_warming_rebuilds_the_read_path_after_a_wipe(db):
    """A restart empties Redis but not Postgres, and readers must not care."""
    db.campaigns.save(_campaign())

    wiped = MemoryStore()
    repo = CampaignRepository(wiped, persistence=db.campaigns)
    assert wiped.get("campaign:1") is None

    assert repo.warm() == 1
    assert wiped.get("campaign:1")


def test_corrections_reach_the_key_value_store_too(db):
    store = MemoryStore()
    memory = FeedbackMemory(store, Settings(), persistence=db.feedback)

    memory.record("Brute Force", "throttle", "temp_block")

    assert json.loads(store.get("feedback:Brute Force")) == {"up": 1, "down": 0}


def test_warming_rebuilds_the_feedback_read_path(db):
    db.feedback.bump("Brute Force", "up")

    wiped = MemoryStore()
    memory = FeedbackMemory(wiped, Settings(), persistence=db.feedback)

    assert memory.warm() == 1
    assert json.loads(wiped.get("feedback:Brute Force")) == {"up": 1, "down": 0}
