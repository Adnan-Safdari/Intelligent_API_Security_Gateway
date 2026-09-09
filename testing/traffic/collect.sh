#!/usr/bin/env bash
#
# Drive a sequence of collection runs.
#
# One run is two containers that have to be started in the right order and left
# alone for ten minutes; twenty-four of them cannot be driven by hand. Per run:
#
#   1. capture starts FIRST and is waited for. A Redis consumer group only sees
#      entries added after the group exists, so traffic sent before capture is
#      ready is traffic no dataset ever hears about.
#   2. traffic runs to completion. A non-zero exit is almost always the
#      pre-flight refusing to send from addresses the gateway will not believe,
#      and that ends the sequence -- a run where every persona collapsed into
#      one address is worse than a missing run, because nothing downstream can
#      detect it.
#   3. capture is left to exit on its own deadline, which is set longer than the
#      traffic so completions still in flight are not truncated into what looks
#      like a quiet final minute.
#
# Each run gets its own seed. Without that the sequence replays one plan
# twenty-four times, which adds rows and almost no variety.
#
# Enforcement state is reset between runs, which matters more than it sounds.
# The pools hand out the same addresses every run, and a two-minute trial was
# enough for the control plane to write `escalate` policies with 57-minute TTLs
# onto seven attacker addresses -- including .180 and .181, the reserved pool.
# Carried into the next run those would arrive already enforced against, and the
# held-out scenarios exist precisely to be traffic the deterministic layer does
# NOT act on. The control plane is stopped for the sequence for the same reason:
# it is the consumer of the model this dataset trains, so letting it enforce
# during collection would teach the model to predict what the current
# hand-tuned agent already blocks.
#
# Resumable: a run whose manifest already records a finish is skipped, so an
# interrupted sequence can be restarted with the same command.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
compose=(docker compose -f "$root/infra/docker-compose.yml")

runs="${1:-24}"
seconds="${TRAFFIC_SECONDS:-600}"
per_persona="${TRAFFIC_PER_PERSONA:-8}"
# Long enough for the traffic plus the settling of in-flight completions. The
# proxy timeout is 30s, so 120 is a wide margin -- and every second past the
# last completion is a second twenty-four runs pay for.
capture_seconds="${CAPTURE_SECONDS:-$((seconds + 120))}"
# pip install in a cold container is most of this; the readiness poll below is
# what actually decides when traffic starts.
ready_timeout="${READY_TIMEOUT:-300}"

if ! docker info >/dev/null 2>&1; then
  echo "collect: the Docker daemon is not running" >&2
  exit 1
fi

if [ -z "$("${compose[@]}" ps -q gateway 2>/dev/null)" ]; then
  cat >&2 <<'MSG'
collect: the gateway is not up. Start it with the collection config first:

  IASG_CONFIG=configs/config.collect.yaml \
    docker compose -f infra/docker-compose.yml up -d gateway

The default config caps iasg:events at 2000 entries, against the ~35000 a
ten-minute run produces. Started on it, most of every run is trimmed away.
MSG
  exit 1
fi

echo "collect: $runs runs, ${seconds}s of traffic each, $per_persona sessions per persona"
echo "collect: nothing else may talk to the gateway until this finishes"

# Stopped unconditionally, not "if it happens to be running". An earlier
# version guarded this on `ps -q control_plane` and skipped the stop whenever
# the container was down at that instant -- which is exactly the case after a
# machine restart, and `restart: unless-stopped` then brought it back a minute
# later, behind the guard. It wrote nine policy keys into the first run before
# anyone noticed. `stop` on an already-stopped container is a no-op, so there
# was never a reason to ask first.
echo "collect: stopping control_plane for the sequence"
"${compose[@]}" stop control_plane >/dev/null 2>&1 || true
echo "collect: restart it afterwards with 'docker compose -f infra/docker-compose.yml start control_plane'"

completed=0
skipped=0
for n in $(seq 1 "$runs"); do
  run_id="run${n}"
  out="$root/datasets/raw/$run_id"

  # Resume rather than redo. finished_at is written by capture's manifest pass,
  # so its presence means that run drained to its deadline.
  if [ -f "$out/manifest.json" ] && grep -q '"finished_at"' "$out/manifest.json"; then
    echo "collect: $run_id already finished, skipping"
    skipped=$((skipped + 1))
    continue
  fi

  echo "collect: === $run_id ($n/$runs) ==="
  rm -rf "$out"

  # Every run starts from the same enforcement state, or runs are not
  # comparable. The policy keys outlive a run by nearly an hour; the gateway's
  # own reflex blocks are in-memory and 300s, so a restart is what clears them.
  # Re-asserted every run: a restart policy can revive the agent mid-sequence,
  # and by the time that shows up in the data the sequence is already spoiled.
  "${compose[@]}" stop control_plane >/dev/null 2>&1 || true

  redis_cli=("${compose[@]}" exec -T redis redis-cli)
  for pattern in 'policy:*' 'campaign:*'; do
    keys="$("${redis_cli[@]}" --scan --pattern "$pattern" 2>/dev/null | tr -d '\r')"
    [ -n "$keys" ] && echo "$keys" | xargs "${redis_cli[@]}" del >/dev/null 2>&1 || true
  done
  # restart, not `up -d`: it reuses the container as created, so the gateway
  # keeps the collect config. `up -d` would recreate it with this shell's
  # environment and silently drop stream_maxlen back to 2000.
  "${compose[@]}" restart gateway >/dev/null

  # Removed rather than reused: `up -d` can hand back the previous run's exited
  # container, which would append this run's entries to the last run's files.
  "${compose[@]}" --profile collect rm -sf capture >/dev/null 2>&1 || true

  RUN_ID="$run_id" CAPTURE_SECONDS="$capture_seconds" \
    "${compose[@]}" --profile collect up -d capture

  # Ready when the health stream is landing on disk: that proves the consumer
  # groups exist and that capture is draining live entries, which neither the
  # container being "up" nor the directory existing does.
  echo "collect: waiting for capture to drain"
  waited=0
  until [ -s "$out/health.jsonl" ]; do
    if [ "$waited" -ge "$ready_timeout" ]; then
      echo "collect: capture never started draining for $run_id" >&2
      "${compose[@]}" --profile collect logs --tail 30 capture >&2 || true
      exit 1
    fi
    sleep 2
    waited=$((waited + 2))
  done

  if ! RUN_ID="$run_id" TRAFFIC_SECONDS="$seconds" TRAFFIC_SEED="$n" \
       TRAFFIC_PER_PERSONA="$per_persona" \
       "${compose[@]}" --profile collect run --rm traffic; then
    echo "collect: traffic failed for $run_id -- stopping the sequence" >&2
    echo "collect: a failed pre-flight means the gateway did not believe our" >&2
    echo "collect: addresses; continuing would collect runs that are silently" >&2
    echo "collect: one client pretending to be many." >&2
    exit 1
  fi

  # Not killed: the last requests' completions arrive after the last arrival.
  echo "collect: letting capture settle"
  container="$("${compose[@]}" --profile collect ps -q capture)"
  [ -n "$container" ] && docker wait "$container" >/dev/null || true

  "${compose[@]}" --profile collect rm -sf capture >/dev/null 2>&1 || true
  completed=$((completed + 1))
  echo "collect: $run_id done ($(wc -l < "$out/arrivals.jsonl" | tr -d ' ') arrivals)"
done

echo "collect: finished -- $completed run(s) collected, $skipped skipped"
echo "collect: build with"
echo "  cd control-plane && PYTHONPATH=. .venv/bin/python -m iasg.dataset.build \\"
echo "    --runs $(for n in $(seq 1 "$runs"); do printf '../datasets/raw/run%s ' "$n"; done)\\"
echo "    --out ../datasets/v2"
