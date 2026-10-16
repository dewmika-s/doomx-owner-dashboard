const corsHeaders = {
  "Access-Control-Allow-Origin": "*", // Restrict to your exact Pages origin after deployment.
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, X-Owner-Session",
  "Content-Type": "application/json; charset=utf-8",
};

const SESSION_MS = 60 * 60 * 1000;
const LIFETIME_MS = 100 * 365.25 * 24 * 60 * 60 * 1000;

function reply(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: corsHeaders });
}
async function sha256(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, "0")).join("");
}
async function hashKey(key) { return sha256(key.trim().toUpperCase()); }
function randomHex(length) {
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}
function makeKey() { return "DX-" + randomHex(24).toUpperCase(); }
function validDeviceId(id) {
  return typeof id === "string" &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id.trim());
}
async function readBody(request) {
  try {
    const body = await request.json();
    return body && typeof body === "object" && !Array.isArray(body) ? body : null;
  } catch { return null; }
}
async function ownerSessionValid(request, env) {
  const token = request.headers.get("X-Owner-Session") || "";
  if (!/^[0-9a-f]{64}$/i.test(token)) return false;
  const tokenHash = await sha256(token);
  const row = await env.DB.prepare(
    "SELECT token_hash FROM owner_sessions WHERE token_hash = ? AND expires_at > ?"
  ).bind(tokenHash, Date.now()).first();
  return !!row;
}
async function findKeyById(env, keyId) {
  if (typeof keyId !== "string" || !/^[0-9a-f]{12}$/i.test(keyId)) return null;
  return env.DB.prepare(
    "SELECT key_hash FROM access_keys WHERE substr(key_hash, 1, 12) = ? LIMIT 1"
  ).bind(keyId).first();
}
async function listKeys(env) {
  const now = Date.now();
  const result = await env.DB.prepare(`
    SELECT key_hash, active, expires_at, device_id, created_at
    FROM access_keys ORDER BY created_at DESC LIMIT 500
  `).all();
  return {
    success: true,
    keys: (result.results || []).map(row => ({
      keyId: row.key_hash.slice(0, 12),
      active: row.active === 1,
      expired: Number(row.expires_at) <= now,
      expiresAt: Number(row.expires_at),
      createdAt: Number(row.created_at),
      deviceBound: !!row.device_id,
      deviceId: row.device_id || null
    }))
  };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders });
    if (request.method === "GET" && path === "/health") {
      return reply({ ok: true, service: "DOOMX Key API" });
    }
    if (!env.DB) return reply({ error: "Database binding DB is missing." }, 500);
    if (request.method !== "POST") return reply({ error: "Use POST for this endpoint." }, 405);

    const body = await readBody(request);
    if (!body) return reply({ error: "Invalid JSON object." }, 400);

    // Master secret is accepted only for login. Never put it in dashboard source.
    if (path === "/owner/login") {
      const supplied = typeof body.secret === "string" ? body.secret : "";
      if (!env.DOOMX_OWNER_SECRET || !supplied || supplied.length > 512 ||
          supplied !== env.DOOMX_OWNER_SECRET) {
        return reply({ error: "Owner login failed." }, 401);
      }
      try {
        const now = Date.now();
        await env.DB.prepare("DELETE FROM owner_sessions WHERE expires_at <= ?").bind(now).run();
        const token = randomHex(32);
        await env.DB.prepare(`
          INSERT INTO owner_sessions (token_hash, expires_at, created_at) VALUES (?, ?, ?)
        `).bind(await sha256(token), now + SESSION_MS, now).run();
        return reply({ success: true, token, expiresAt: now + SESSION_MS });
      } catch {
        return reply({ error: "Could not create owner session. Check owner_sessions table." }, 500);
      }
    }

    if (path.startsWith("/owner/")) {
      if (!await ownerSessionValid(request, env)) {
        return reply({ error: "Owner session expired or invalid. Please sign in again." }, 401);
      }

      if (path === "/owner/logout") {
        const token = request.headers.get("X-Owner-Session") || "";
        await env.DB.prepare("DELETE FROM owner_sessions WHERE token_hash = ?")
          .bind(await sha256(token)).run();
        return reply({ success: true });
      }

      if (path === "/owner/create") {
        const duration = body.duration;
        const durations = {
          "24h": 24 * 60 * 60 * 1000,
          "7d": 7 * 24 * 60 * 60 * 1000,
          "30d": 30 * 24 * 60 * 60 * 1000,
          "1y": 365.25 * 24 * 60 * 60 * 1000,
          "lifetime": LIFETIME_MS
        };
        if (!Object.prototype.hasOwnProperty.call(durations, duration)) {
          return reply({ error: "Choose 24h, 7d, 30d, 1y, or lifetime." }, 400);
        }
        try {
          const now = Date.now(), expiresAt = now + durations[duration], key = makeKey();
          await env.DB.prepare(`
            INSERT INTO access_keys (key_hash, active, expires_at, device_id, created_at)
            VALUES (?, 1, ?, NULL, ?)
          `).bind(await hashKey(key), expiresAt, now).run();
          return reply({ success: true, key, duration, expiresAt,
            message: "Copy and save this key now; it cannot be retrieved later." }, 201);
        } catch {
          return reply({ error: "Could not create key. Check access_keys schema." }, 500);
        }
      }

      if (path === "/owner/list") {
        try { return reply(await listKeys(env)); }
        catch { return reply({ error: "Could not list access keys." }, 500); }
      }

      if (path === "/owner/revoke") {
        const key = typeof body.key === "string" ? body.key.trim() : "";
        if (key.length < 12 || key.length > 100) return reply({ error: "Provide a valid key." }, 400);
        try {
          const result = await env.DB.prepare("UPDATE access_keys SET active = 0 WHERE key_hash = ?")
            .bind(await hashKey(key)).run();
          return reply({ success: true, revoked: result.meta.changes > 0 });
        } catch { return reply({ error: "Could not revoke key." }, 500); }
      }

      if (path === "/owner/set-active") {
        if (typeof body.active !== "boolean") return reply({ error: "active must be true or false." }, 400);
        try {
          const row = await findKeyById(env, body.keyId);
          if (!row) return reply({ error: "Key not found." }, 404);
          const result = await env.DB.prepare("UPDATE access_keys SET active = ? WHERE key_hash = ?")
            .bind(body.active ? 1 : 0, row.key_hash).run();
          return reply({ success: true, changed: result.meta.changes > 0 });
        } catch { return reply({ error: "Could not update key." }, 500); }
      }

      if (path === "/owner/delete") {
        try {
          const row = await findKeyById(env, body.keyId);
          if (!row) return reply({ error: "Key not found." }, 404);
          const result = await env.DB.prepare("DELETE FROM access_keys WHERE key_hash = ?")
            .bind(row.key_hash).run();
          return reply({ success: true, deleted: result.meta.changes > 0 });
        } catch { return reply({ error: "Could not delete key." }, 500); }
      }

      if (path === "/owner/deactivate-all") {
        if (body.confirmation !== "DEACTIVATE ALL") return reply({ error: "Confirmation required." }, 400);
        try {
          const result = await env.DB.prepare("UPDATE access_keys SET active = 0 WHERE active = 1").run();
          return reply({ success: true, changed: result.meta.changes });
        } catch { return reply({ error: "Could not deactivate all keys." }, 500); }
      }

      if (path === "/owner/delete-all") {
        if (body.confirmation !== "DELETE ALL KEYS") return reply({ error: "Confirmation required." }, 400);
        try {
          const result = await env.DB.prepare("DELETE FROM access_keys").run();
          return reply({ success: true, deleted: result.meta.changes });
        } catch { return reply({ error: "Could not delete all keys." }, 500); }
      }

      return reply({ error: "Unknown owner endpoint." }, 404);
    }

    // Keep the existing customer API behavior and device binding.
    if (path !== "/activate" && path !== "/validate") return reply({ error: "Endpoint not found." }, 404);

    const key = typeof body.key === "string" ? body.key.trim() : "";
    if (key.length < 12 || key.length > 100) {
      return reply({ valid: false, error: "Access key must be between 12 and 100 characters." }, 400);
    }
    const deviceId = typeof body.deviceId === "string" ? body.deviceId.trim() : "";
    if (!validDeviceId(deviceId)) {
      return reply({ valid: false, error: "Invalid device ID format. A UUID is required." }, 400);
    }

    try {
      const keyHash = await hashKey(key), now = Date.now();
      await env.DB.prepare(`
        UPDATE access_keys SET device_id = COALESCE(device_id, ?)
        WHERE key_hash = ? AND active = 1 AND expires_at > ?
          AND (device_id IS NULL OR device_id = ?)
      `).bind(deviceId, keyHash, now, deviceId).run();

      const row = await env.DB.prepare(
        "SELECT active, expires_at, device_id FROM access_keys WHERE key_hash = ?"
      ).bind(keyHash).first();

      if (!row || row.active !== 1) return reply({ valid: false, error: "Invalid or revoked key." }, 403);
      if (Number(row.expires_at) <= now) return reply({ valid: false, error: "Key expired." }, 403);
      if (row.device_id !== deviceId) {
        return reply({ valid: false, error: "This key is already bound to another device." }, 403);
      }
      return reply({ valid: true, expiresAt: Number(row.expires_at) });
    } catch {
      return reply({ valid: false, error: "Server error while validating the key." }, 500);
    }
  }
};
