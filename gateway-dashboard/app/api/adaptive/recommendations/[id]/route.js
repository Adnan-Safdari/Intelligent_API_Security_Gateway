import { require as requireRole } from "@/lib/auth";
import { validateRecommendationEdit } from "@/lib/adaptive";
import { getPool } from "@/lib/postgres";

export const dynamic = "force-dynamic";

export async function PATCH(request, { params }) {
  const gate = await requireRole("operator");
  if (gate.denied) return gate.denied;
  const pool = getPool();
  if (!pool) return Response.json({ ok: false, error: "durable store unavailable" }, { status: 503 });
  const { id } = await params;
  let body;
  try {
    body = await request.json();
  } catch {
    return Response.json({ ok: false, error: "expected JSON" }, { status: 400 });
  }
  if (!['approve', 'reject'].includes(body.decision)) {
    return Response.json({ ok: false, error: "decision must be approve or reject" }, { status: 400 });
  }

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const rowResult = await client.query(
      "SELECT payload,status FROM policy_recommendations WHERE policy_id=$1 FOR UPDATE",
      [id],
    );
    const settingsResult = await client.query(
      "SELECT config FROM adaptive_settings WHERE singleton_id=1",
    );
    const row = rowResult.rows[0];
    const config = settingsResult.rows[0]?.config;
    if (!row || !config) throw new ApiError(404, "recommendation or settings not found");
    if (row.status !== "pending_approval") throw new ApiError(409, "recommendation is no longer pending");

    let status = "rejected";
    let payload = row.payload;
    if (body.decision === "approve") {
      const edits = body.edits || {};
      payload = {
        ...payload,
        action: edits.action || payload.action,
        requests_per_minute: edits.requests_per_minute ?? payload.requests_per_minute,
        expires_in: edits.duration_seconds ?? payload.expires_in,
        reason: String(edits.reason || payload.reason || "").slice(0, 500),
        source: "approved",
        issued_by: gate.user.username,
        issued_at: new Date().toISOString(),
      };
      const problem = validateRecommendationEdit(payload, config);
      if (problem) throw new ApiError(400, problem);
      payload.expires_at = new Date(Date.now() + Number(payload.expires_in) * 1000).toISOString();
      status = "approved";
    }
    await client.query(
      `UPDATE policy_recommendations
          SET action=$2,status=$3,issued_by=$4,expires_at=$5,payload=$6::jsonb,updated_at=now()
        WHERE policy_id=$1`,
      [id, payload.action, status, gate.user.username, payload.expires_at, JSON.stringify(payload)],
    );
    await client.query(
      "INSERT INTO policy_audit (policy_id,event,actor,details) VALUES ($1,$2,$3,$4::jsonb)",
      [id, status, gate.user.username, JSON.stringify({ edited: body.edits || {} })],
    );
    await client.query("COMMIT");
    return Response.json({ ok: true, policyId: id, status });
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    return Response.json({ ok: false, error: err.message }, { status: err.status || 503 });
  } finally {
    client.release();
  }
}

class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}
