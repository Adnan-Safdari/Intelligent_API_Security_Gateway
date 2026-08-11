"""
The agent loop (section 12).

    observe -> correlate -> remember -> decide -> explain

Runs every interval_seconds. Evidence is acked only once a cycle completes,
so a crash mid-cycle replays rather than loses it.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from iasg.assessment.agent import AssessmentAgent
from iasg.campaigns.repository import CampaignRepository
from iasg.config import Settings
from iasg.correlation.agent import CorrelationAgent
from iasg.evidence.consumer import EvidenceConsumer
from iasg.explanation.agent import ExplanationAgent
from iasg.models import Campaign
from iasg.policy.agent import PolicyAgent
from iasg.policy.writer import PolicyWriter
from iasg.reasoning import open_provider
from iasg.store import open_store
from iasg.store.base import Store


@dataclass
class CycleResult:
    evidence_count: int = 0
    campaigns: list[Campaign] = None
    policies_written: int = 0
    notes: list[str] = None

    def __post_init__(self) -> None:
        if self.campaigns is None:
            self.campaigns = []
        if self.notes is None:
            self.notes = []


class Runner:
    def __init__(self, settings: Settings, store: Store | None = None) -> None:
        self.settings = settings
        self.store = store or open_store(settings)

        provider = open_provider(settings)
        self.consumer = EvidenceConsumer(self.store, settings)
        self.correlation = CorrelationAgent()
        self.campaigns = CampaignRepository(self.store)
        self.policy = PolicyAgent()
        self.writer = PolicyWriter(self.store, settings)
        self.explanation = ExplanationAgent(provider)
        self.assessment = AssessmentAgent(provider)

    def cycle(self) -> CycleResult:
        result = CycleResult()

        # 1. observe
        evidence = self.consumer.fetch()
        result.evidence_count = len(evidence)
        if not evidence:
            return result

        # 2. correlate, then 3. remember
        fresh = self.correlation.analyse(evidence)
        campaigns = self.campaigns.merge(fresh)
        result.campaigns = campaigns

        for campaign in campaigns:
            # 4. decide -- rules only, no LLM anywhere near this
            decisions = self.policy.decide(campaign)
            written, notes = self.writer.write(decisions)
            result.policies_written += written
            result.notes.extend(notes)

            # 5. explain -- advisory text, after the decision is already made
            campaign.explanation = self.explanation.explain(campaign, decisions)
            campaign.assessment = self.assessment.review(campaign)
            self.campaigns.save(campaign)

        # Ack last: everything above succeeded, so this evidence is truly done.
        self.consumer.ack(evidence)
        return result

    def run_forever(self) -> None:
        print(
            f"[iasg] control plane started "
            f"(every {self.settings.interval_seconds}s, "
            f"dry_run={self.settings.dry_run})"
        )
        while True:
            try:
                report(self.cycle())
            except KeyboardInterrupt:
                print("\n[iasg] stopped")
                return
            except Exception as err:
                # One bad cycle must not end the agent.
                print(f"[iasg] cycle failed: {err}")
            time.sleep(self.settings.interval_seconds)


def report(result: CycleResult) -> None:
    """Print one cycle in the shape the proposal's demo output describes."""
    print(f"\n[cycle] read {result.evidence_count} events")
    if not result.campaigns:
        if result.evidence_count:
            print("        no campaigns formed")
        return

    for c in result.campaigns:
        plural = "IP" if len(c.ips) == 1 else "IPs"
        print(f"[correlation] Campaign #{c.campaign_id} -- {c.type}")
        print(
            f"              {len(c.ips)} {plural}, "
            f"confidence {c.confidence:.2f}, {c.severity}"
        )
        print(f"              {c.reason}")
        if c.explanation:
            print(f"[explain]     {c.explanation}")
        if c.assessment:
            print(f"[assess]      {c.assessment}")

    print(f"[policy]      wrote {result.policies_written} policy keys")
    for note in result.notes:
        print(f"              {note}")
