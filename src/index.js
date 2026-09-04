const json = (data, status = 200) => Response.json(data, { status, headers: { "cache-control": "no-store" } });

function hexToBytes(hex) {
  if (!/^[0-9a-f]{64}$/i.test(hex || "")) return null;
  return new Uint8Array(hex.match(/.{2}/g).map((value) => parseInt(value, 16)));
}

async function verifyHmac(body, signature, secret) {
  const bytes = hexToBytes(signature);
  if (!bytes || !secret) return false;
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"]
  );
  return crypto.subtle.verify("HMAC", key, bytes, new TextEncoder().encode(body));
}

function clean(value, max = 160) {
  return String(value ?? "-").replace(/[\u0000-\u001F\u007F]/g, " ").trim().slice(0, max);
}

function messageFor(path, data) {
  const code = clean(data.code, 32);
  if (path !== "/api/test" && !/^KS-BR-[0-9]{6}-[A-F0-9]{8}$/.test(code)) return null;
  if (path === "/api/test") return "✅ اتصال امن وب‌سایت AdliSho به Worker و تلگرام برقرار است.";
  if (path === "/api/submit") {
    return `🗂 ثبت پرونده جدید\n\nکد: ${code}\nاستان: ${clean(data.province, 60)}\nعنوان: ${clean(data.job, 140)}\nزمان: ${clean(data.time, 50)}`;
  }
  if (path === "/api/follow") {
    return `🔄 به‌روزرسانی پرونده\n\nکد: ${code}\nرویداد: ${clean(data.event, 60)}\nتوضیح: ${clean(data.note, 240)}\nزمان: ${clean(data.time, 50)}`;
  }
  return null;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/health")) {
      return json({
        ok: true,
        service: "AdliSho Telegram Relay",
        version: "2.0.0",
        ready: Boolean(env.TG_BOT_TOKEN && env.TG_CHAT_ID && env.RELAY_SECRET)
      });
    }
    if (request.method !== "POST") return json({ ok: false, error: "method_not_allowed" }, 405);
    if (!["/api/submit", "/api/follow", "/api/test"].includes(url.pathname)) return json({ ok: false, error: "not_found" }, 404);
    if (!env.TG_BOT_TOKEN || !env.TG_CHAT_ID || !env.RELAY_SECRET) return json({ ok: false, error: "secrets_not_configured" }, 500);
    if (!(request.headers.get("content-type") || "").toLowerCase().includes("application/json")) return json({ ok: false, error: "json_required" }, 415);
    const contentLength = Number(request.headers.get("content-length") || 0);
    if (contentLength > 8192) return json({ ok: false, error: "payload_too_large" }, 413);
    const raw = await request.text();
    if (raw.length > 8192) return json({ ok: false, error: "payload_too_large" }, 413);
    if (!(await verifyHmac(raw, request.headers.get("X-AdliSho-Signature"), env.RELAY_SECRET))) return json({ ok: false, error: "unauthorized" }, 401);
    let data;
    try { data = JSON.parse(raw); } catch { return json({ ok: false, error: "invalid_json" }, 400); }
    const text = messageFor(url.pathname, data);
    if (!text) return json({ ok: false, error: "invalid_payload" }, 422);

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 8000);
    try {
      const telegram = await fetch(`https://api.telegram.org/bot${env.TG_BOT_TOKEN}/sendMessage`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ chat_id: env.TG_CHAT_ID, text, disable_web_page_preview: true }),
        signal: controller.signal
      });
      const result = await telegram.json().catch(() => null);
      if (!telegram.ok) return json({ ok: false, error: "telegram_rejected", status: telegram.status }, 502);
      return json({ ok: true, delivered: Boolean(result?.ok) });
    } catch {
      return json({ ok: false, error: "telegram_unreachable" }, 502);
    } finally {
      clearTimeout(timer);
    }
  }
};
