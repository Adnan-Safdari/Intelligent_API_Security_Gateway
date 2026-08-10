# Brute Force Detection — Demo Guide

How to run the brute force attack demo against the Intelligent API Security Gateway.

**Important:** this detector **detects but does not block**. Following the project's design rule
("detectors emit metrics; the centralized decision engine decides"), every request is forwarded
to the backend. The proof of detection is the **SECURITY ALERT in the gateway console**, not a
blocked response.

---

## 0. One-time setup (run once, then never again)

Copy-paste this whole block into a terminal:

```bash
echo 'export PATH="$HOME/.local/go/bin:$PATH"' >> ~/.zshrc
echo 'export JAVA_HOME="$HOME/.local/java/jdk-21.0.12+8/Contents/Home"' >> ~/.zshrc
echo 'export PATH="$JAVA_HOME/bin:$PATH"' >> ~/.zshrc
source ~/.zshrc
```

Check it worked — both commands must print a version:

```bash
go version      # go1.26.5
java -version   # openjdk 21.0.12
```

---

## 1. Quick test (30 seconds, no servers needed)

Proves the detection logic with unit tests:

```bash
cd ~/Intelligent_API_Security_Gateway/gateway
go test ./internal/signals/ -v
```

Expected: 6 tests `PASS`, including `TestBruteForceNeverBlocks` which asserts that
every request still reaches the backend.

---

## 2. Full demo (3 terminals)

### Terminal 1 — the victim backend
```bash
cd ~/mock-login-backend && go run .
```
Wait for: `mock backend on :5002`

### Terminal 2 — the gateway  ← KEEP THIS VISIBLE, THIS IS THE STAR
```bash
cd ~/Intelligent_API_Security_Gateway/gateway && go run ./cmd/server
```
Wait for: `Gateway starting on 0.0.0.0:8082`

### Terminal 3 — the attacker

**Option A — curl (fastest):**
```bash
for i in {1..8}; do
  curl -s -o /dev/null -w "attempt $i: %{http_code}\n" -X POST http://localhost:8082/api/login \
    -H "Content-Type: application/json" -d "{\"email\":\"admin\",\"password\":\"wrong$i\"}"
done
```

**Option B — JMeter (for the panel):**
```bash
cd ~/jmeter-demo && ./JMeter/apache-jmeter-5.6.3/bin/jmeter -t brute_force_demo.jmx
```
Then in the JMeter window:
1. Click **View Results in Table** in the left tree
2. Click the green **▶ Start** button

---

## 3. What proves it works

| Where | What you see |
|---|---|
| Terminal 3 / JMeter | **Every** attempt returns `401` — the attacker never knows they were spotted |
| Terminal 2 (gateway) | From the 5th failure: `SECURITY ALERT: BRUTE FORCE DETECTED` with failed login count, distinct users, attack type, severity |

For the panel: put **JMeter on the left, gateway terminal on the right** so both are visible at once.
Point at the gateway terminal — that alert is the deliverable.

### Talking point

> "The attacker sees only ordinary 401s and has no idea they've been detected — we don't tip them
> off. Meanwhile the gateway has recorded the evidence: 5 failed logins from one IP in 60 seconds,
> against a single account. That evidence is exposed as metrics for the decision engine, which owns
> the Allow / Throttle / Block call for the whole system."

---

## 4. Extra things to demonstrate

**Password spraying detection** (many accounts, one password):
```bash
for i in {1..6}; do
  curl -s -o /dev/null -w "spray $i: %{http_code}\n" -X POST http://localhost:8082/api/login \
    -H "Content-Type: application/json" -d "{\"email\":\"user$i@x.com\",\"password\":\"Summer2026\"}"
done
```
The alert switches to `PASSWORD SPRAYING (multiple accounts)` with `Distinct Users: 5`.
Same detector, different attack shape — worth showing.

**Successful login resets the counter** (no false positives for real users):
```bash
# 3 wrong, then correct, then 3 more wrong -> alert never fires
for p in wrongA wrongB wrongC adminPassword123 wrongD wrongE wrongF; do
  curl -s -o /dev/null -w "$p: %{http_code}\n" -X POST http://localhost:8082/api/login \
    -H "Content-Type: application/json" -d "{\"email\":\"admin\",\"password\":\"$p\"}"
done
```

**Non-login traffic is ignored** (the detector is targeted, not noisy):
```bash
for i in {1..10}; do
  curl -s -o /dev/null http://localhost:8082/api/products
done
```
No alert — only configured `login_paths` are watched.

---

## 5. Resetting between demos

The detector keeps a 60-second sliding window in memory. To start completely fresh:
- **Restart the gateway** (Ctrl+C in Terminal 2, then `go run ./cmd/server`) — clears all state
- In JMeter, click the **broom icon** (Clear All) to wipe old rows

---

## 6. Tuning the thresholds

Edit `gateway/configs/config.yaml`, then restart the gateway:

```yaml
enforcement:
  brute_force:
    enabled: true
    max_failures: 5 # failed logins inside the window before the signal fires
    window: 60s     # sliding window size
    login_paths:
      - "/api/login"
```

Good live demo: change `max_failures` to `3`, restart, and show the alert now fires after 3 attempts.

---

## 7. The metrics it emits

The detector's real output is `Metrics(ip)`, which the future decision engine will consume
alongside the other signals:

```go
type BruteForceMetrics struct {
    FailedLogins   int    // failures inside the current window
    DistinctUsers  int    // distinct emails tried (spraying indicator)
    ThresholdCross bool   // failures >= configured max
    AttackType     string // "brute_force" | "password_spraying" | ""
}
```

This matches the metrics shape described in `gateway/docs/project-context.md` §8.1.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `command not found: go` / `java` | Re-run step 0 |
| `address already in use` | `lsof -ti:8082 \| xargs kill` |
| Connection refused | Terminal 1 (backend) isn't running |
| No alert appears | You need **5** failures within **60 seconds** — send them in one burst |
| `directory not found` on gateway start | You must `cd` into `~/Intelligent_API_Security_Gateway/gateway` first |

---

## Note on the backend

`~/mock-login-backend` is a small Go stand-in for `vulnerable-app/backend` (which needs Node.js, not installed).
It behaves identically for login: `admin` / `adminPassword123` succeeds, everything else returns 401.

If you install Node later, use the real one instead:
```bash
cd ~/Intelligent_API_Security_Gateway/vulnerable-app/backend && npm install && npm start
```
Caveat: avoid test passwords containing `'`, `--`, or the letters "OR" — the vulnerable app's
simulated SQL-injection check turns those into fake *successful* logins.
