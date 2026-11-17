const UPDATE_PATH = "/_natmap";
const LEASE_MS = 180_000;
const NO_CACHE = { "Cache-Control": "no-store" };
const encoder = new TextEncoder();

function isPublicIPv4(ip) {
  if (typeof ip !== "string") return false;
  const parts = ip.split(".");
  if (parts.length !== 4) return false;
  const octets = parts.map(Number);
  if (octets.some((value, index) => !Number.isInteger(value) ||
      value < 0 || value > 255 || String(value) !== parts[index])) {
    return false;
  }

  const [a, b, c, d] = octets;
  // Exclude non-global and retired special-use blocks, multicast and reserved space.
  return !(
    a === 0 || a === 10 || a === 127 || a >= 224 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && (b === 168 || (b === 88 && c === 99) ||
      (b === 0 && (c === 2 || (c === 0 && d !== 9 && d !== 10))))) ||
    (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) ||
    (a === 203 && b === 0 && c === 113)
  );
}

function authorized(request, token) {
  if (!token) return false;
  const expected = encoder.encode(`Bearer ${token}`);
  const supplied = encoder.encode(request.headers.get("Authorization") ?? "");
  return supplied.length === expected.length &&
    crypto.subtle.timingSafeEqual(supplied, expected);
}

export default {
  async fetch(request, env) {
    const { pathname } = new URL(request.url);
    const project = env.NATMAP_PROJECT ?? "";
    if (pathname === UPDATE_PATH && request.method === "PUT") {
      if (!authorized(request, env.REDIRECT_TOKEN)) {
        return new Response(null, { status: 401, headers: NO_CACHE });
      }
      let payload;
      try {
        payload = await request.json();
      } catch {
        return new Response("Invalid JSON", { status: 400, headers: NO_CACHE });
      }
      const { ip, port, scheme } = payload ?? {};
      if (!isPublicIPv4(ip) || !Number.isInteger(port) || port < 1 || port > 65535 ||
          (scheme !== "http" && scheme !== "https")) {
        return new Response("Invalid public IPv4, port or scheme", { status: 400, headers: NO_CACHE });
      }
      const target = new URL(`${scheme}://${ip}`);
      target.port = String(port);
      await env.REDIRECT_DB.prepare(`
        INSERT INTO natmap_projects (project, location, expires_at) VALUES (?, ?, ?)
        ON CONFLICT(project) DO UPDATE SET location = excluded.location, expires_at = excluded.expires_at
      `).bind(project, target.href, Date.now() + LEASE_MS).run();
      return new Response(null, { status: 204, headers: NO_CACHE });
    }

    if (pathname !== "/" || (request.method !== "GET" && request.method !== "HEAD")) {
      return new Response(null, { status: 404, headers: NO_CACHE });
    }
    const location = await env.REDIRECT_DB.prepare(`
      SELECT location FROM natmap_projects WHERE project = ? AND expires_at > ?
    `).bind(project, Date.now()).first("location");
    if (!location) {
      return new Response(
        request.method === "HEAD" ? null : "电脑暂时离线或正在重新打洞，请稍后重试。",
        {
          status: 503,
          headers: { ...NO_CACHE, "Content-Type": "text/plain; charset=utf-8", "Retry-After": "15" },
        },
      );
    }
    return new Response(null, { status: 302, headers: { ...NO_CACHE, Location: location } });
  },
};
