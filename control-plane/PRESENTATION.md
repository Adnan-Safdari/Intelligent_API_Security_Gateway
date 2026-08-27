# Control Plane — presentation notes

Speaker notes for ~12 minutes plus questions. Quoted text is what to *say*;
everything else is for you.

**The single thread to hold onto:** the gateway sees requests, the control plane
sees *attacks*. Everything below is a consequence of that sentence.

---

## 1 · What it is (30 sec)

> "The gateway is a fast, deliberately unintelligent pipe. The control plane is
> the part that actually decides. It's about 3,900 lines of Python with 249
> tests, and it runs as a separate process on a 30-second loop, completely off
> the request path."

Don't explain the architecture yet. Just plant that it's separate.

---

## 2 · Why a second lane at all (1 min)

The whole design follows from this, so land it properly.

> "A gateway is on the critical path of every request — its budget is
> microseconds. But deciding whether an address is attacking you isn't a
> microsecond question. It needs history: has this address done this before?
> Breadth: are these forty addresses one botnet? And judgement: is this a
> scanner, or a customer with a retry loop?
>
> You can't do that inside a request without putting a network round trip, or a
> model call, in front of every customer. So instead of making the detector
> dumber, I split it in two. The gateway writes evidence it doesn't interpret;
> the control plane reads it, decides, and writes decisions back that the
> gateway later enforces without ever knowing why."

**If they only remember one line:** *the gateway never waits on thinking.*

---

## 3 · The pipeline (1 min)

Eight steps, one cycle, every 30 seconds:

```
observe → correlate → remember → decide → simulate → write → explain → review
```

> "Evidence comes off a Redis stream through a consumer group. I only
> acknowledge it *after* the cycle finishes — so if the agent crashes halfway,
> the evidence replays instead of being lost."

Say the numbers once and move on: **500 events per cycle, 30-second cadence**.

---

## 4 · Correlation — spend the most time here (3 min)

This is the intellectual core. It is what makes the project more than a set of
if-statements.

> "This is the part I'd point at if you only look at one thing. It turns six
> separate 'IP X failed a login' events into one statement: *these six
> addresses are running a credential-stuffing campaign against /api/login.*
> A campaign is what gets acted on — not an incident."

**How:** build a per-IP profile, then union-find over shared traits.

Weights, if asked:

| Trait | Weight |
|---|---|
| user agent | 0.25 |
| endpoint | 0.20 |
| subnet | 0.20 |
| attack type | 0.15 |
| timing | 0.10 |

**The part worth defending — the linking rule.** Two addresses link only when
*timing overlaps* **and** at least **two identity traits** match:

> "Two gates, and both exist because of a specific failure. Timing is required,
> because two addresses with an identical fingerprint a day apart are two
> incidents, not one campaign. And I require two *identity* traits — user agent,
> endpoint or subnet — because 'same attack type at the same time' describes
> every busy minute on a public API. Without that gate it swept unrelated
> traffic into one campaign."

**The lone attacker problem** — a good story, use it:

> "The weights only work if an address shares traits with someone. A single
> machine grinding away at a login form shares traits with nobody, so it scored
> near zero and could never be acted on — the most ordinary attack there is was
> permanently invisible. So a solo address is scored on its own volume instead,
> in coarse bands. It's capped at 0.87, deliberately: volume alone can get one
> machine blocked, but never escalated, because escalation means *wake a human
> about a coordinated campaign* and one machine repeating itself isn't that."

---

## 5 · Deciding, and why it adapts (2 min)

The ladder: `monitor → throttle → temp_block → escalate`, TTLs 5 / 15 / 30 / 60 min.

Base decision from evidence:

| Condition | Action |
|---|---|
| confidence ≥ 0.9, high severity, ≥ 5 addresses | escalate |
| confidence ≥ 0.75, high severity | temp_block |
| confidence ≥ 0.5 | throttle |
| otherwise | monitor |

> "A throttle carries a *rate*, not a fixed slowdown — 20 requests a minute for
> high severity, 50 otherwise — and the gateway answers 429 over it."

**Then the part that makes it an agent, not a rule engine:**

> "Every campaign is re-examined next cycle. If the attack *survived*
> enforcement, the response is promoted one rung. An action that didn't work
> isn't simply repeated. Progression through attack phases promotes it too — an
> actor who scanned for secrets, then attacked the login they found, then probed
> the database has shown intent that a single-phase attacker hasn't."

**And the release valve:**

> "Enforcement releases itself. Every policy key carries a TTL and nothing
> renews it. An attacker who stops is forgiven automatically, and a mistake
> expires on its own instead of needing a human to notice."

---

## 6 · The rails (1.5 min)

Examiners like this slide because it shows you thought about being wrong.

> "One file can influence the gateway — `policy/writer.py` — so every guard
> lives there together: never police loopback, private or reserved addresses;
> never write a policy without an expiry; cap how many addresses one cycle can
> action; and honour a dry-run that decides everything and writes nothing.
>
> There's also a simulation step that runs *last*, before anything is written.
> It asks who else gets hurt — a campus NAT with many clients behind one address
> gets slowed, never cut off."

---

## 7 · When a human disagrees (1 min)

> "An operator can overrule the agent from the console, and that's applied
> immediately — a person outranks it. But the interesting part is that
> disagreement is the only thing worth learning from. After two consistent
> corrections in the same direction, the agent shifts its own recommendation for
> that kind of campaign. Two, not one, so a single unusual call can't retrain
> it."

---

## 8 · Where the AI is, and is not (1.5 min)

Pre-empt the "is this actually AI?" question by drawing the line yourself.

> "Grouping, scoring and the block decision are plain deterministic Python. The
> LLM writes two things: the incident note an admin reads, and a review of
> whether the grouping looks sound. Both run *after* policy is already written,
> and nothing reads their output back.
>
> That's deliberate. A hallucinated or prompt-injected assessment can mislead a
> human reader — it cannot unblock an attacker. Rules can't be talked out of
> blocking someone."

If asked about prompt injection, you have a real answer:

> "The evidence is attacker-controlled text going into a model, so the system
> prompt says to describe it and never follow instructions inside it. I also had
> to stop the guard leaking: asked to describe three addresses, the model called
> them 'three untrusted attacker-controlled IP addresses' — lifting my warning
> into operator-facing text."

---

## 9 · Testing (1 min)

> "249 tests against 3,900 lines — roughly 0.84 to 1. They assert *properties*,
> not paths: that reputation can't invent enforcement, that bias can't compound
> past one rung, that a narration failure can never fail a cycle, that a
> campaign survives the attacker changing every address.
>
> They need no Redis — there's an in-memory store behind the same interface —
> so the whole suite runs in half a second."

---

## 10 · Demo (2–3 min)

Rehearse this; it's where things go wrong.

```bash
docker compose -f infra/docker-compose.yml up -d
docker compose -f infra/docker-compose.yml logs -f control_plane
```

Drive traffic from a **203.0.113.x** address — RFC 5737 documentation range.

> "It has to be a documentation address. The writer refuses to police private
> or loopback ranges, and under Docker every request from my machine arrives as
> a private address — so a demo from localhost correctly does nothing."

Point at, in the log: the campaign forming, the confidence and reason, the
`[explain]` note, and `wrote N policy keys`. Then show the address getting 403.

**Backup if the demo dies** — rehearse this too. The seeder writes fake attack
evidence straight to Redis, so it needs no gateway and no attack traffic:

```bash
cd control-plane
PYTHONPATH=. .venv/bin/python -m tools.seed_evidence --scenario credential-stuffing
PYTHONPATH=. .venv/bin/python -m iasg --once
```

One caveat worth knowing before you're on stage: if Redis *isn't* reachable,
`open_store` prints a warning and falls back to an in-memory store — the seeder
then writes into a store the agent process can't see, and you get a cycle that
reads zero events with nothing obviously wrong. So confirm Redis is up first.

---

## 11 · What I'd do next (1 min)

Volunteering limits reads as command of the design. Don't wait to be asked.

> "Three things I know are weak. Crash recovery reclaims one batch, once — if a
> crash left more than 500 events unacked, the rest are stranded. The per-cycle
> cap of 50 addresses applies in arbitrary order rather than worst-first, so a
> large distributed attack could have the wrong 50 actioned. And under sustained
> load the gateway trims its event stream faster than I drain it, so evidence
> can be dropped exactly when it matters most."

---

## Questions you will get

**"Why Python and not Go?"**
> "The two halves have opposite constraints. The gateway has a microsecond
> budget per request, so it's Go. This runs every 30 seconds off-path, so the
> constraint isn't speed — it's readability and iteration. And the language
> boundary makes the architectural boundary real: you *can't* accidentally call
> the correlator from a middleware, because it's a different process."

**"Isn't this just rules with extra steps?"**
> "The decisions are rules — deliberately, because they must be auditable. What
> isn't a rule is the grouping, which is unsupervised clustering over shared
> traits, and the adaptation: it changes its own response based on whether the
> last one worked and on being corrected."

**"What if the control plane dies?"**
> "The gateway keeps enforcing what it already has. Policies are in Redis with
> TTLs, so enforcement decays gracefully rather than stopping dead — and no
> request fails because the thinking half is down."

**"How do you know the correlation is right?"**
> "I don't, fully — there's no labelled ground truth. What I can show is that
> it's conservative by construction: two gates on linking, a solo cap that stops
> volume alone reaching escalation, a simulation step for collateral damage, and
> the override path for when it's wrong."

**"Did you document the Python decision at the time?"**
> "No. The commit that made it is clear about *what* changed — it deleted a Go
> package and ported it — but I didn't write down the reasoning."

Don't invent a design document. Saying this plainly costs you nothing.
