/**
 * NUMINT live-intelligence Worker
 * Proxies IPQualityScore phone validation so the API key stays server-side.
 *
 * Setup (Cloudflare dashboard):
 *   1. Workers & Pages -> Create -> Worker. Paste this in, deploy.
 *   2. Settings -> Variables and Secrets -> add a SECRET named  IPQS_KEY  = your IPQS private key.
 *   3. Copy the worker URL (e.g. https://numint.YOURNAME.workers.dev) into numint.html (WORKER_URL).
 *
 * The key is NEVER in the frontend or in this file. Rotate the key you pasted in chat.
 */

const ALLOWED_ORIGINS = [
  "https://allainborno.tech",
  "https://www.allainborno.tech",
];

export default {
  async fetch(request, env) {
    const origin = request.headers.get("Origin") || "";
    const allowOrigin = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
    const cors = {
      "Access-Control-Allow-Origin": allowOrigin,
      "Access-Control-Allow-Methods": "GET, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: cors });
    }

    const url = new URL(request.url);
    const phone = url.searchParams.get("phone");
    if (!phone) {
      return json({ error: "missing phone parameter" }, 400, cors);
    }

    const key = env.IPQS_KEY;
    if (!key) {
      return json({ error: "worker not configured: set IPQS_KEY secret" }, 500, cors);
    }

    const api =
      "https://ipqualityscore.com/api/json/phone/" +
      encodeURIComponent(key) +
      "/" +
      encodeURIComponent(phone);

    try {
      const resp = await fetch(api, { cf: { cacheTtl: 0 } });
      const d = await resp.json();

      if (!d || d.success === false) {
        return json({ error: (d && d.message) || "lookup failed" }, 502, cors);
      }

      // Return only the fields the UI needs (don't leak the full payload).
      return json(
        {
          valid: d.valid,
          active: d.active,
          carrier: d.carrier || null,
          line_type: d.line_type || null,
          voip: d.VOIP === true,
          prepaid: d.prepaid === true,
          city: d.city || null,
          region: d.region || null,
          country: d.country || null,
          fraud_score: typeof d.fraud_score === "number" ? d.fraud_score : null,
          recent_abuse: d.recent_abuse === true,
          risky: d.risky === true,
          spammer: d.spammer === true,
        },
        200,
        cors
      );
    } catch (e) {
      return json({ error: "upstream request failed" }, 502, cors);
    }
  },
};

function json(obj, status, cors) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json", ...cors },
  });
}
