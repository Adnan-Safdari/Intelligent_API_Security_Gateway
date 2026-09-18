# Control-plane presentation notes

The key architectural statement is: **the gateway sees requests; the control
plane sees campaigns; the gateway never waits on thinking.**

1. Gateway detectors observe flooding, injection, brute force, reconnaissance,
   object enumeration, ownership violations, and reputation. Detectors emit
   evidence; they do not refuse the request they inspect.
2. The control plane learns a per-endpoint baseline from complete, clean
   windows using median and MAD. Warm-up, bounds, hysteresis, and cooldown
   keep learning stable.
3. Correlation groups coordinated IPs through overlapping time and shared
   traits. It preserves campaigns through both partial member overlap and IP
   rotation.
4. The adaptive policy engine combines deterministic evidence, baseline
   deviation, and campaign facts into explainable risk and confidence values.
5. Monitor mode records recommendations, manual mode requires an analyst, and
   automatic mode writes only guardrail-compliant temporary policies.

Important safety points: no deterministic evidence means monitor; reputation
cannot originate action; every policy has a TTL; unsafe addresses are rejected;
and narration is post-decision only.
