// Control API — HTTPS (self-signed) when certs exist, HTTP otherwise.
// Every route except /health requires the bearer key.

const http = require("http");
const https = require("https");
const crypto = require("crypto");
const identity = require("./identity");

const RATE_LIMIT = 120; // authed requests / minute / ip
const hits = new Map(); // ip -> {count, reset}

function rateLimited(ip) {
  const now = Date.now();
  const e = hits.get(ip);
  if (!e || now > e.reset) {
    hits.set(ip, { count: 1, reset: now + 60000 });
    return false;
  }
  return ++e.count > RATE_LIMIT;
}

const err = (status, message) => Object.assign(new Error(message), { status });

const readBody = (req) =>
  new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (c) => {
      data += c;
      if (data.length > 64 * 1024) req.destroy();
    });
    req.on("end", () => {
      try {
        resolve(data ? JSON.parse(data) : {});
      } catch {
        reject(err(400, "bad JSON"));
      }
    });
    req.on("error", reject);
  });

const authed = (req, token) => {
  const given = Buffer.from(
    (req.headers.authorization || "").replace(/^Bearer\s+/i, "")
  );
  const want = Buffer.from(token);
  return given.length === want.length && crypto.timingSafeEqual(given, want);
};

// routes: { "GET /info": fn, "POST /peers": fn, "DELETE /peers/:key": fn }
function serve({ port, token, tls, routes }) {
  const handler = async (req, res) => {
    const send = (status, obj) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(obj));
    };
    try {
      const url = new URL(req.url, "https://x");
      const path = url.pathname;

      if (req.method === "GET" && path === "/health") {
        return send(200, { ok: true, version: routes.VERSION });
      }
      if (rateLimited(req.socket.remoteAddress)) {
        return send(429, { ok: false, error: "rate limited" });
      }
      if (!authed(req, token)) {
        return send(401, { ok: false, error: "unauthorized" });
      }

      for (const [route, fn] of Object.entries(routes)) {
        if (!route.includes(" ")) continue; // skip VERSION/dir meta keys
        const [method, pattern] = route.split(" ");
        if (method !== req.method) continue;
        const params = match(pattern, path);
        if (!params) continue;
        const body = method === "POST" ? await readBody(req) : {};
        return send(200, { ok: true, data: await fn(body, params) });
      }
      return send(404, { ok: false, error: "not found" });
    } catch (e) {
      return send(e.status || 500, { ok: false, error: e.message || String(e) });
    }
  };

  const server = tls
    ? https.createServer(
        { cert: identity.cert(routes.dir), key: identity.key(routes.dir) },
        handler
      )
    : http.createServer(handler);

  server.listen(port, "0.0.0.0");
  return tls ? "https" : "http";
}

// "/peers/:key" vs "/peers/AbC=" → {key:"AbC="}
function match(pattern, path) {
  const pp = pattern.split("/");
  const ap = path.split("/");
  if (pp.length !== ap.length) return null;
  const params = {};
  for (let i = 0; i < pp.length; i++) {
    if (pp[i].startsWith(":")) params[pp[i].slice(1)] = decodeURIComponent(ap[i]);
    else if (pp[i] !== ap[i]) return null;
  }
  return params;
}

module.exports = { serve };
