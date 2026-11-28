/*
 * MNS Collections – permanent QR endpoint
 * https://mnscollections.pages.dev/scan
 *
 * The QR code on cards and packaging always points here. Change where it goes
 * by editing CONFIG below (commit to main → Cloudflare Pages redeploys), or by
 * setting the same keys as environment variables in the Cloudflare dashboard
 * (Pages project → Settings → Variables and Secrets). Environment variables
 * win over CONFIG.
 *
 *   SCAN_MODE         coming_soon | amazon | website
 *   SCAN_AMAZON_URL   https://www.amazon.in/...   (Amazon domains only)
 *   SCAN_WEBSITE_URL  https://...
 *
 * Anything missing or invalid falls back to the coming-soon page, never an error.
 */
const CONFIG = {
  SCAN_MODE: "coming_soon",
  SCAN_AMAZON_URL: "",
  SCAN_WEBSITE_URL: "",
};

const AMAZON_HOST = /(^|\.)amazon\.(in|com)$|^amzn\.(to|in|eu)$/i;

function setting(env, key) {
  const v = env && typeof env[key] === "string" ? env[key].trim() : "";
  return v || CONFIG[key];
}

function safeUrl(raw, amazonOnly) {
  try {
    const u = new URL(raw);
    if (u.protocol !== "https:") return null;
    if (amazonOnly && !AMAZON_HOST.test(u.hostname)) return null;
    return u.toString();
  } catch {
    return null;
  }
}

function redirect(location) {
  return new Response(null, {
    status: 302,
    headers: {
      Location: location,
      "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
      "CDN-Cache-Control": "no-store",
      "Referrer-Policy": "no-referrer-when-downgrade",
    },
  });
}

async function comingSoon(context) {
  const res = await context.next(); // serves the static /scan page (scan.html)
  const out = new Response(res.body, res);
  // Short browser cache so a later switch to a redirect takes effect quickly.
  out.headers.set("Cache-Control", "public, max-age=0, must-revalidate");
  out.headers.set("X-Robots-Tag", "noindex");
  return out;
}

export async function onRequest(context) {
  const { request, env } = context;
  if (request.method !== "GET" && request.method !== "HEAD") return comingSoon(context);

  const mode = (setting(env, "SCAN_MODE") || "coming_soon").toLowerCase();

  if (mode === "amazon") {
    const dest = safeUrl(setting(env, "SCAN_AMAZON_URL"), true);
    if (dest) return redirect(dest);
  } else if (mode === "website") {
    const dest = safeUrl(setting(env, "SCAN_WEBSITE_URL"), false);
    if (dest) return redirect(dest);
  }
  return comingSoon(context);
}
