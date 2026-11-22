const UPDATE_PATH = "/_natmap";
const COMMAND_PATH = "/_natmap/remote";
const DEVICES_PATH = "/_natmap/tcp-devices";
const RDP_PAGE = "/remote/";
const TCP_PAGE = "/tcp/";
const DEVICES_PAGE = "/remote/group/";
const LOOKUP_ASSETS = new Set(["/remote/connection.js", "/remote/connection.css"]);
const PROJECT_NAME = /^[a-z0-9](?:[a-z0-9-]{0,38}[a-z0-9])?$/;
const LEASE_MS = 180_000;
const NO_CACHE = { "Cache-Control": "no-store" };
const REMOTE_HEADERS = {
  ...NO_CACHE,
  "Referrer-Policy": "no-referrer",
  "X-Robots-Tag": "noindex, nofollow",
  "X-NATMap-Remote-Version": "13",
};
const encoder = new TextEncoder();
const WEB_PROXY_HEADERS = { "X-NATMap-Entry-Mode": "proxy" };

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

async function serveRemoteAsset(request, env, pathname) {
  const assetRequest = new Request(new URL(pathname, request.url), request);
  const asset = await env.ASSETS.fetch(assetRequest);
  const headers = new Headers(asset.headers);
  for (const [name, value] of Object.entries(REMOTE_HEADERS)) headers.set(name, value);
  headers.set("Content-Security-Policy", "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'self'; base-uri 'none'; frame-ancestors 'none'");
  return new Response(asset.body, { status: asset.status, headers });
}

function parseUrl(value, base) {
  try {
    return new URL(value, base);
  } catch {
    return null;
  }
}

function tcpEndpoint(location) {
  const match = location?.match(/^(tcp|tcp-address):\/\/((\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5}))$/);
  if (!match || !isPublicIPv4(match[3]) || Number(match[4]) < 1 || Number(match[4]) > 65535) return null;
  return { address: match[2], rdp: match[1] === "tcp" };
}

function validDevices(devices, project) {
  return Array.isArray(devices) && devices[0]?.id === project &&
    devices.every(device => typeof device?.id === "string" && PROJECT_NAME.test(device.id)
      && typeof device.name === "string" && device.name.trim() && [...device.name].length <= 60) &&
    new Set(devices.map(device => device.id)).size === devices.length;
}

function readDirectory(row, project) {
  if (!row) return [];
  try {
    const devices = JSON.parse(row.location);
    return validDevices(devices, project) ? devices : [];
  } catch {
    return [];
  }
}

async function deviceList(env, project) {
  const { results } = await env.REDIRECT_DB.prepare(
    "SELECT project, location, expires_at FROM natmap_projects WHERE project = ? OR project GLOB ?",
  ).bind(project, `${project}/*`).all();
  const mappings = new Map(results.map(row => [row.project, row]));
  const now = Date.now();
  return readDirectory(mappings.get(`${project}/`), project).map(({ id, name }) => {
    const row = mappings.get(id === project ? project : `${project}/${id}`);
    const endpoint = tcpEndpoint(row?.location);
    const state = !row ? "pending" : !endpoint ? "invalid" : row.expires_at > now ? "available" : "expired";
    return { id, name, address: state === "available" ? endpoint.address : "", rdp: endpoint?.rdp ?? false, state };
  });
}

function proxyError(message) {
  return new Response(message, {
    status: 502,
    headers: { ...NO_CACHE, ...WEB_PROXY_HEADERS, "Content-Type": "text/plain; charset=utf-8" },
  });
}

async function resolveOriginAddresses(host, type) {
  const url = new URL("https://cloudflare-dns.com/dns-query");
  url.searchParams.set("name", host);
  url.searchParams.set("type", type);
  const response = await fetch(url, {
    headers: { Accept: "application/dns-json" }, redirect: "manual",
  });
  if (!response.ok) throw new Error("DNS lookup failed");
  const result = await response.json();
  if (result.Status !== 0) throw new Error("DNS lookup failed");
  return result.Answer ?? [];
}

async function webUpstream(visitor, origin, env) {
  const upstream = new URL(origin);
  if (origin.protocol === "https:") {
    const hostname = env.NATMAP_PROXY_ORIGIN;
    if (!hostname || hostname === visitor.hostname) {
      throw new Error("请在项目设置中填写与目标服务证书匹配的 HTTPS 回源域名。");
    }
    let addresses;
    try {
      addresses = await Promise.all([
        resolveOriginAddresses(hostname, "A"), resolveOriginAddresses(hostname, "AAAA"),
      ]);
    } catch {
      throw new Error("暂时无法解析 HTTPS 回源域名。");
    }
    const [ipv4, ipv6] = addresses;
    const aRecords = ipv4.filter(record => record.type === 1);
    if (!aRecords.length || aRecords.some(record => record.data !== origin.hostname)
        || ipv6.some(record => record.type === 28)) {
      throw new Error("HTTPS 回源域名的 DNS 记录需要指向当前 NATMap 公网 IPv4。");
    }
    upstream.hostname = hostname;
  } else {
    upstream.hostname = origin.hostname.replaceAll(".", "-") + ".sslip.io";
  }
  upstream.pathname = visitor.pathname;
  upstream.search = visitor.search;
  return upstream;
}

async function proxyWeb(request, visitor, origin, upstream) {
  const headers = new Headers(request.headers);
  headers.set("Host", origin.protocol === "https:" ? upstream.host : origin.host);
  headers.set("X-Forwarded-Host", visitor.host);
  headers.set("X-Forwarded-Proto", visitor.protocol.slice(0, -1));
  headers.delete("Forwarded");
  headers.delete("X-Forwarded-Port");
  headers.delete("X-Forwarded-For");
  const clientIp = request.headers.get("CF-Connecting-IP");
  if (clientIp) headers.set("X-Forwarded-For", clientIp);

  let response;
  try {
    response = await fetch(upstream, {
      method: request.method, headers, body: request.body,
      redirect: "manual", cache: "no-store",
    });
  } catch {
    return proxyError("暂时无法连接目标网页服务，请检查公网映射和回源证书。");
  }
  if (response.status === 101) return response;

  const output = new Headers(response.headers);
  const location = output.get("Location");
  if (location && /^(?:https?:)?\/\//i.test(location)) {
    const redirect = parseUrl(location, upstream);
    if (redirect && [origin.host, upstream.host, visitor.host].includes(redirect.host)) {
      const result = new URL(visitor.origin);
      result.pathname = redirect.pathname;
      result.search = redirect.search;
      result.hash = redirect.hash;
      output.set("Location", result.href);
    }
  }
  const cookies = output.getAll("Set-Cookie");
  if (cookies.length) {
    output.delete("Set-Cookie");
    for (const cookie of cookies) {
      const adjusted = cookie.replace(/;\s*Domain\s*=\s*([^;]+)/i, (attribute, domain) => {
        const host = domain.trim().toLowerCase().replace(/^\./, "");
        return host === upstream.hostname || host === origin.hostname ? "" : attribute;
      });
      output.append("Set-Cookie", adjusted);
    }
  }
  output.set("X-NATMap-Entry-Mode", "proxy");
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers: output });
}

function redirectWeb(location) {
  return new Response(null, { status: 302, headers: { ...NO_CACHE, Location: location, "X-NATMap-Entry-Mode": "redirect" } });
}

export default {
  async fetch(request, env) {
    const visitor = new URL(request.url);
    const { pathname } = visitor;
    const project = env.NATMAP_PROJECT ?? "";
    const httpsOnly = env.NATMAP_HTTPS_ONLY === "1";
    if (httpsOnly && visitor.protocol !== "https:") {
      visitor.protocol = "https:";
      return new Response(null, { status: 308, headers: { ...NO_CACHE, Location: visitor.href } });
    }
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
      const { ip, port, scheme, device, directory } = payload ?? {};
      if (!isPublicIPv4(ip) || !Number.isInteger(port) || port < 1 || port > 65535 ||
          !["http", "https", "tcp", "tcp-address"].includes(scheme) || (httpsOnly && scheme !== "https")) {
        return new Response("Invalid public IPv4, port or scheme", { status: 400, headers: NO_CACHE });
      }
      const tcp = scheme === "tcp" || scheme === "tcp-address";
      if ((device !== undefined || directory !== undefined) &&
          (!PROJECT_NAME.test(project) || !validDevices(directory?.devices, project)
           || !Number.isSafeInteger(directory.revision) || directory.revision < 1
           || !directory.devices.some(row => row.id === device)
           || (!tcp && (device !== project || directory.devices.length !== 1)))) {
        return new Response("Invalid TCP device directory", { status: 400, headers: NO_CACHE });
      }
      const target = new URL(`${scheme}://${ip}:${port}`);
      const key = device && device !== project ? `${project}/${device}` : project;
      const mappingUpdate = env.REDIRECT_DB.prepare(`
        INSERT INTO natmap_projects (project, location, expires_at) VALUES (?, ?, ?)
        ON CONFLICT(project) DO UPDATE SET location = excluded.location, expires_at = excluded.expires_at
      `).bind(key, target.href, Date.now() + LEASE_MS);
      if (directory) {
        const directoryUpdate = env.REDIRECT_DB.prepare(`
          INSERT INTO natmap_projects (project, location, expires_at) VALUES (?, ?, ?)
          ON CONFLICT(project) DO UPDATE SET location = excluded.location, expires_at = excluded.expires_at
          WHERE excluded.expires_at >= natmap_projects.expires_at
        `).bind(`${project}/`, JSON.stringify(directory.devices), directory.revision);
        await env.REDIRECT_DB.batch([mappingUpdate, directoryUpdate]);
      } else {
        await mappingUpdate.run();
      }
      return new Response(null, { status: 204, headers: NO_CACHE });
    }

    const proxy = env.NATMAP_WEB_MODE === "proxy";
    const reading = request.method === "GET" || request.method === "HEAD";
    if (pathname === DEVICES_PATH) {
      if (!reading || httpsOnly || !PROJECT_NAME.test(project)) {
        return new Response(null, { status: 404, headers: NO_CACHE });
      }
      if (request.method === "HEAD") return new Response(null, { headers: REMOTE_HEADERS });
      return Response.json(await deviceList(env, project), { headers: REMOTE_HEADERS });
    }
    const remote = pathname === COMMAND_PATH;
    const lookupAsset = LOOKUP_ASSETS.has(pathname);
    const lookupPage = pathname === RDP_PAGE || pathname === TCP_PAGE;
    if (pathname === UPDATE_PATH || (!reading && (remote || !proxy))) {
      return new Response(null, { status: 404, headers: NO_CACHE });
    }
    if (!proxy && !httpsOnly && lookupAsset) {
      return serveRemoteAsset(request, env, pathname);
    }
    if (!proxy && !httpsOnly && !remote && !lookupPage && pathname !== "/") {
      return new Response(null, { status: 404, headers: NO_CACHE });
    }
    let mapping;
    if (reading && pathname === "/" && !httpsOnly && PROJECT_NAME.test(project)) {
      const { results } = await env.REDIRECT_DB.prepare(
        "SELECT project, location, expires_at FROM natmap_projects WHERE project IN (?, ?)",
      ).bind(project, `${project}/`).all();
      if (readDirectory(results.find(row => row.project === `${project}/`), project).length > 1) {
        return serveRemoteAsset(request, env, DEVICES_PAGE);
      }
      mapping = results.find(row => row.project === project);
    } else {
      mapping = await env.REDIRECT_DB.prepare(`
        SELECT location, expires_at FROM natmap_projects WHERE project = ?
      `).bind(project).first();
    }
    const location = mapping?.expires_at > Date.now() ? mapping.location : "";
    if (httpsOnly && location && !location.startsWith("https://")) {
      return proxyError("管理页入口需要 HTTPS 回源。");
    }
    if (remote) {
      const endpoint = tcpEndpoint(location);
      if (!endpoint) {
        return new Response(null, { status: 503, headers: { ...REMOTE_HEADERS, "Retry-After": "15" } });
      }
      return new Response(request.method === "HEAD" ? null : endpoint.address, {
        headers: { ...REMOTE_HEADERS, "Content-Type": "text/plain; charset=utf-8" },
      });
    }
    const storedLocation = mapping?.location ?? "";
    const genericTCP = storedLocation.startsWith("tcp-address://");
    if (genericTCP || storedLocation.startsWith("tcp://") || (!proxy && !httpsOnly && lookupPage)) {
      if (!reading || (!lookupAsset && !lookupPage && pathname !== "/")) {
        return new Response(null, { status: 404, headers: NO_CACHE });
      }
      const page = genericTCP || pathname === TCP_PAGE ? TCP_PAGE : RDP_PAGE;
      return serveRemoteAsset(request, env, lookupAsset ? pathname : page);
    }
    if (!location || !/^https?:\/\//.test(location)) {
      return new Response(
        request.method === "HEAD" ? null : "电脑暂时离线或正在重新打洞，请稍后重试。",
        {
          status: 503,
          headers: { ...NO_CACHE, "Content-Type": "text/plain; charset=utf-8", "Retry-After": "15" },
        },
      );
    }
    if (proxy || httpsOnly) {
      const origin = parseUrl(location);
      if (!origin || !isPublicIPv4(origin.hostname)) return proxyError("暂无有效的公网回源地址。");
      let upstream;
      try {
        upstream = await webUpstream(visitor, origin, env);
      } catch (error) {
        return proxyError(error.message);
      }
      return proxy ? proxyWeb(request, visitor, origin, upstream) : redirectWeb(upstream.href);
    }
    return redirectWeb(location);
  },
};
