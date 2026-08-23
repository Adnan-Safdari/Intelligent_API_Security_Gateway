"""
The agent loop (section 12).

    observe -> correlate -> remember -> decide -> explain

Runs every interval_seconds. Evidence is acked only once a cycle completes,
so a crash mid-cycle replays rather than loses it.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone

from iasg.alerts import AlertSink
from iasg.assessment.agent import AssessmentAgent
from iasg.campaigns.repository import CampaignRepository
from iasg.config import Settings
from iasg.correlation.agent import CorrelationAgent
from iasg.evidence.consumer import EvidenceConsumer
from iasg.explanation.agent import ExplanationAgent
from iasg.feedback import overrides as human
from iasg.feedback.memory import FeedbackMemory
from iasg.feedback.overrides import OverrideChannel
from iasg.models import ACTION_ESCALATE, ACTION_MONITOR, Campaign
from iasg.policy.agent import PolicyAgent
from iasg.policy.simulation import Simulator
from iasg.policy.writer import PolicyWriter
from iasg.reasoning import open_provider
from iasg.store import open_store
from iasg.store.base import Store
from iasg.store.postgres import open_database


@dataclass
class CycleResult:
    evidence_count: int = 0
    campaigns: list[Campaign] = None
    policies_written: int = 0
    notes: list[str] = None
    # Older campaigns whose status changed this cycle.
    reviewed: list[Campaign] = None
    # Campaigns escalated to a human this cycle.
    escalated: list[Campaign] = None
    # Campaigns a human overruled this cycle.
    overridden: list[Campaign] = None
    # Policy written purely on a human's instruction, about addresses no
    # campaign mentioned.
    manual: list = None
    # What the agent has learned from past overrides and applied this cycle.
    learned: list[str] = None
    # Narration calls the cycle refused because its budget was spent. Reported
    # so a campaign reading as a bare template is explained rather than
    # looking like the LLM silently broke.
    narration_skipped: int = 0

    def __post_init__(self) -> None:
        if self.campaigns is None:
            self.campaigns = []
        if self.notes is None:
            self.notes = []
        if self.reviewed is None:
            self.reviewed = []
        if self.escalated is None:
            self.escalated = []
        if self.overridden is None:
            self.overridden = []
        if self.manual is None:
            self.manual = []
        if self.learned is None:
            self.learned = []


class Runner:
    def __init__(self, settings: Settings, store: Store | None = None) -> None:
        self.settings = settings
        self.store = store or open_store(settings)

        provider = open_provider(settings)
        # Optional and non-fatal: without it campaigns stay in Redis under a
        # TTL, which is the behaviour every test and the default deployment use.
        self.database = open_database(settings)

        self.consumer = EvidenceConsumer(self.store, settings)
        self.correlation = CorrelationAgent()
        self.campaigns = CampaignRepository(
            self.store,
            persistence=self.database.campaigns if self.database else None,
        )
        self.policy = PolicyAgent()
        self.simulator = Simulator(self.store, settings)
        self.overrides = OverrideChannel(self.store, settings)
        self.feedback = FeedbackMemory(
            self.store,
            settings,
            persistence=self.database.feedback if self.database else None,
        )
        if self.database:
            restored = self.campaigns.warm() + self.feedback.warm()
            if restored:
                print(f"[postgres] restored {restored} records into Redis")

        self.writer = PolicyWriter(self.store, settings)
        self.provider = provider
        self.explanation = ExplanationAgent(provider)
        self.assessment = AssessmentAgent(provider)
        self.alerts = AlertSink(self.store)

    def cycle(self) -> CycleResult:
        result = CycleResult()

        # Narration is capped per cycle, not per call, so the allowance has to
        # be restored before any campaign spends it. Providers without a
        # budget -- NullProvider -- have nothing to reset.
        begin = getattr(self.provider, "begin_cycle", None)
        if begin:
            begin()

        # Read before anything is decided, and applied whether or not there was
        # an attack this cycle: an admin blocking an address should not have to
        # wait for the agent to notice a campaign first.
        pending = {o.ip: o for o in self.overrides.pending()}

        # 1. observe
        evidence = self.consumer.fetch()
        result.evidence_count = len(evidence)

        # 2. correlate, then 3. remember
        campaigns = (
            self.campaigns.merge(self.correlation.analyse(evidence))
            if evidence
            else []
        )
        result.campaigns = campaigns

        covered: set[str] = set()
        for campaign in campaigns:
            self._respond(campaign, evidence, pending, result)
            covered.update(campaign.ips)

        # Instructions about addresses no campaign mentioned. Blocking an
        # address the agent has never seen is the plainest use of an override.
        loose = human.standalone(pending, covered)
        if loose:
            # Through the same gate, so an allowlisted range is protected from
            # a mistyped instruction exactly as it is from the agent.
            result.manual, notes = self.simulator.review(loose, evidence)
            result.notes.extend(notes)
            written, notes = self.writer.write(result.manual)
            result.policies_written += written
            result.notes.extend(notes)

        # 6. review -- did acting on the older campaigns change anything? A
        # cycle with no evidence is not a wasted one: silence is the signal.
        result.reviewed = self.campaigns.review({c.campaign_id for c in campaigns})

        self._beat(result)

        result.narration_skipped = getattr(self.provider, "skipped", 0)

        # Ack last: everything above succeeded, so this evidence is truly done.
        if evidence:
            self.consumer.ack(evidence)
        return result

    def _beat(self, result: CycleResult) -> None:
        """
        Say the agent is alive, and when it last thought.

        Given a TTL of a few intervals, the key's *absence* is the signal: a
        console reading it cannot tell a stopped agent from a quiet network
        otherwise, and those two look identical while meaning opposite things.
        Best effort -- failing to announce a cycle must not fail the cycle.
        """
        try:
            self.store.set(
                self.settings.heartbeat_key,
                json.dumps(
                    {
                        "at": datetime.now(timezone.utc).isoformat(),
                        "interval_seconds": self.settings.interval_seconds,
                        "evidence": result.evidence_count,
                        "campaigns": len(result.campaigns),
                        "policies_written": result.policies_written,
                        "durable": bool(self.database),
                        "dry_run": self.settings.dry_run,
                    }
                ),
                ttl_seconds=max(self.settings.interval_seconds * 3, 90),
            )
        except Exception as err:  # noqa: BLE001 - liveness is not worth a cycle
            print(f"[heartbeat] could not record this cycle ({err})")

    def _respond(self, campaign, evidence, pending, result: CycleResult) -> None:
        """Decide, check the decision is safe, let a human overrule it, write."""
        # 4. decide -- rules only, no LLM anywhere near this
        bias = self.feedback.bias_for(campaign.type)
        decisions = self.policy.decide(campaign, bias=bias)
        if bias:
            result.learned.append(self.feedback.explain(campaign.type))

        # 4b. a person outranks the agent, and disagreeing with us is the only
        # thing here worth learning from.
        decisions, lessons, notes = human.apply(decisions, pending)
        result.notes.extend(notes)
        for agent_action, human_action in lessons:
            self.feedback.record(campaign.type, agent_action, human_action)
            result.overridden.append(campaign)

        # 4c. simulate -- last, so nothing reaches the gateway without passing
        # the safety checks, whoever asked for it.
        decisions, notes = self.simulator.review(decisions, evidence)
        result.notes.extend(notes)

        written, notes = self.writer.write(decisions)
        result.policies_written += written
        result.notes.extend(notes)

        # What was actually applied, not what was first proposed -- the next
        # cycle judges whether this worked.
        campaign.last_action = decisions[0].action if decisions else ACTION_MONITOR

        # 5. explain -- advisory text, after the decision is already made
        campaign.explanation = self.explanation.explain(campaign, decisions)
        campaign.assessment = self.assessment.review(campaign)

        # Escalation is the one action that asks for a person. Raised
        # after the explanation so the alert carries something readable.
        if campaign.last_action == ACTION_ESCALATE:
            if self.alerts.raise_for(campaign, decisions):
                result.escalated.append(campaign)

        self.campaigns.save(campaign)

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

    for line in result.learned:
        print(f"[learned]     {line}")

    for decision in result.manual:
        print(f"[human]       {decision.ip} -> {decision.action} ({decision.reason})")

    if not result.campaigns:
        if result.evidence_count:
            print("        no campaigns formed")
        if result.manual:
            print(f"[policy]      wrote {result.policies_written} policy keys")
        # A quiet cycle is when the review has something to say, so it must
        # be printed before returning.
        _report_review(result)
        return

    for c in result.campaigns:
        plural = "IP" if len(c.ips) == 1 else "IPs"
        print(f"[correlation] Campaign #{c.campaign_id} -- {c.type}")
        print(
            f"              {len(c.ips)} {plural}, "
            f"confidence {c.confidence:.2f}, {c.severity}"
        )
        print(f"              {c.reason}")
        if len(c.stages) > 1:
            print(
                f"[stages]      {' -> '.join(c.stages)} "
                f"({len(c.stages)} phases, not {len(c.stages)} separate attacks)"
            )
        if c.rotations:
            changes = "change" if c.rotations == 1 else "changes"
            print(
                f"[continuity]  re-identified by behaviour through "
                f"{c.rotations} address {changes}"
            )
        if c.persistence:
            rounds = "round" if c.persistence == 1 else "rounds"
            print(
                f"[adapt]       survived {c.persistence} enforcement {rounds} "
                f"-- responding with {c.last_action or 'no action'}"
            )
        if c.explanation:
            print(f"[explain]     {c.explanation}")
        if c.assessment:
            print(f"[assess]      {c.assessment}")

    print(f"[policy]      wrote {result.policies_written} policy keys")
    if result.narration_skipped:
        print(
            f"[llm]         narration budget spent -- "
            f"{result.narration_skipped} call(s) fell back to templates"
        )
    for note in result.notes:
        print(f"              {note}")

    _report_review(result)


def _report_review(result: CycleResult) -> None:
    """Anything raised for a human, and what became of older campaigns."""
    for c in result.escalated:
        print(
            f"[escalate]    Campaign #{c.campaign_id} raised for human review "
            f"-- {len(c.ips)} IPs, confidence {c.confidence:.2f}"
        )

    for c in result.reviewed:
        if c.status == "contained":
            print(f"[review]      Campaign #{c.campaign_id} contained -- {c.outcome}")
        else:
            print(
                f"[review]      Campaign #{c.campaign_id} quiet for "
                f"{c.quiet_cycles} cycle(s) after {c.last_action or 'no action'}"
            )
