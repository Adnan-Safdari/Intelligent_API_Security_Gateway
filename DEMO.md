# Brute Force Detection — Demo Guide

How to run the brute force attack demo against the Intelligent API Security Gateway.

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

Expected: 4 tests `PASS`, plus a sample SECURITY ALERT printed.

---

## 2. Full demo (3 terminals)

### Terminal 1 — the victim backend
```bash
cd ~/mock-login-backend && go run .
```
Wait for: `mock backend on :5002`

### Terminal 2 — the gateway  ← KEEP THIS VISIBLE
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
| Terminal 3 / JMeter | Attempts 1-5 → `401`, attempts 6+ → `429` |
| Terminal 2 (gateway) | `SECURITY ALERT: BRUTE FORCE DETECTED` box, `IP LOCKED OUT FOR 2m0s` |

For the panel: put **JMeter on the left, gateway terminal on the right** so both are visible at once.

---

## 4. Extra things to demonstrate

**Even the correct password is blocked during lockout:**
```bash
curl -s -o /dev/null -w "%{http_code}\n" -X POST http://localhost:8082/api/login \
  -H "Content-Type: application/json" -d '{"email":"admin","password":"adminPassword123"}'
```
Returns `429` — the attacker is locked out regardless.

**Password spraying detection** (many accounts, one password):
```bash
for i in {1..6}; do
  curl -s -o /dev/null -w "spray $i: %{http_code}\n" -X POST http://localhost:8082/api/login \
    -H "Content-Type: application/json" -d "{\"email\":\"user$i@x.com\",\"password\":\"Summer2026\"}"
done
```
The alert now says `PASSWORD SPRAYING (multiple accounts)` with `Distinct Users: 5`.

**Successful login resets the counter:**
```bash
# 3 wrong, then correct, then 3 more wrong -> never locks out
for p in wrongA wrongB wrongC adminPassword123 wrongD wrongE wrongF; do
  curl -s -o /dev/null -w "$p: %{http_code}\n" -X POST http://localhost:8082/api/login \
    -H "Content-Type: application/json" -d "{\"email\":\"admin\",\"password\":\"$p\"}"
done
```

---

## 5. Resetting between demos

The lockout lasts **2 minutes**. To demo again immediately:
- **Restart the gateway** (Ctrl+C in Terminal 2, then `go run ./cmd/server`) — clears all state
- In JMeter, click the **broom icon** (Clear All) to wipe old rows

---

## 6. Tuning the thresholds

Edit `gateway/configs/config.yaml`, then restart the gateway:

```yaml
enforcement:
  brute_force:
    enabled: true
    max_failures: 5        # failures allowed in the window
    window: 60s            # sliding window size
    lockout_duration: 120s # ban length (0s = log only, never block)
    login_paths:
      - "/api/login"
```

Good live demo: change `max_failures` to `3`, restart, and show it now blocks after 3 attempts.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `command not found: go` / `java` | Re-run step 0 |
| `address already in use` | `lsof -ti:8082 \| xargs kill` |
| All requests return `429` immediately | You're still locked out from a previous run — restart the gateway |
| Connection refused | Terminal 1 (backend) isn't running |

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
