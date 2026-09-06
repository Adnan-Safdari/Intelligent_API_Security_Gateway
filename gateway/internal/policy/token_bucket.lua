-- Value and TTL must still belong to the observed decision. A deleted,
-- replaced, or unexpiring key cannot keep throttling through a stale cache.
local policy_ttl = nil
if #KEYS > 1 then
    if redis.call('GET', KEYS[2]) ~= ARGV[3] then
        return {1, 0, 'policy_inactive'}
    end
    policy_ttl = redis.call('PTTL', KEYS[2])
    if policy_ttl <= 0 then
        return {1, 0, 'policy_inactive'}
    end
end

local rpm = tonumber(ARGV[1])
local capacity = math.min(tonumber(ARGV[2]), rpm)
local clock = redis.call('TIME')
local now = tonumber(clock[1]) * 1000 + tonumber(clock[2]) / 1000
local state = redis.call('HMGET', KEYS[1], 'tokens', 'updated_ms')
local tokens = tonumber(state[1]) or capacity
local updated = tonumber(state[2]) or now

-- A backwards clock adjustment must not mint tokens when time catches up.
now = math.max(now, updated)
tokens = math.min(capacity, tokens + (now - updated) * rpm / 60000)

local allowed = 0
local wait = 0
local reason = 'quota_exhausted'
if tokens >= 1 then
    allowed = 1
    tokens = tokens - 1
    reason = 'within_quota'
else
    wait = math.ceil((1 - tokens) * 60000 / rpm)
    if policy_ttl then
        wait = math.min(wait, policy_ttl)
    end
end

-- Once a bucket would be full, forgetting it is equivalent to retaining it.
-- Capping at the policy TTL also removes every old generation automatically.
local lifetime = math.max(1, math.ceil(capacity * 60000 / rpm))
if policy_ttl then
    lifetime = math.min(lifetime, policy_ttl)
end
redis.call('HSET', KEYS[1], 'tokens', tokens, 'updated_ms', now)
redis.call('PEXPIRE', KEYS[1], lifetime)
return {allowed, wait, reason}
