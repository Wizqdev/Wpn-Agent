/**
 * @fileoverview Control API HTTP/HTTPS server.
 *
 * Serves HTTPS (self-signed TLS) when certs are available, plain HTTP
 * otherwise.  Every route except `GET /health` requires a valid Bearer token.
 *
 * Rate limiting is enforced per source IP (120 authenticated requests/minute).
 * The `public` meta-key on the routes object lists route strings that skip
 * the bearer check (e.g. `"GET /speedtest"`).
 *
 * Public routes still count against the rate-limit bucket so they can't be
 * used to enumerate the API structure from behind DDoS.
 */

"use strict";

const http   = require("http");
const https  = require("https");
const crypto = require("crypto");
const identity = require("./identity");

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

/** Maximum authenticated requests per minute per source IP. */
const RATE_LIMIT = 120;

/** @type {Map<string, {count: number, reset: number}>} */
const hits = new Map();

/** Sweep the rate-limit map when it exceeds this many entries. */
const RATE_SWEEP_AT = 4_096;

/**
 * @param {string} ip
 * @returns {boolean} `true` if this IP has exceeded the rate limit.
 */
function rateLimited(ip) {
  const now = Date.now();
  const e   = hits.get(ip);
  if (!e || now > e.reset) {
    hits.set(ip, { count: 1, reset: now + 60_000 });
    // Lazy sweep — keep the map bounded.
    if (hits.size > RATE_SWEEP_AT) {
      for (const [k, v] of hits) if (now > v.reset) hits.delete(k);
    }
    return false;
  }
  return ++e.count > RATE_LIMIT;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Create a tagged Error with an HTTP status code attached.
 *
 * @param {number} status
 * @param {string} message
 * @returns {Error & {status: number}}
 */
const err = (status, message) => Object.assign(new Error(message), { status });

/**
 * Buffer the full request body and parse it as JSON.
 * Destroys the socket if the body exceeds 64 KiB.
 *
 * @param {import("http").IncomingMessage} req
 * @returns {Promise<object>}
 */
const readBody = (req) =>
  new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (c) => {
      data += c;
      if (data.length > 64 * 1_024) req.destroy();
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

/**
 * Constant-time bearer token comparison.
 *
 * @param {import("http").IncomingMessage} req
 * @param {string} token
 * @returns {boolean}
 */
const authed = (req, token) => {
  const given = Buffer.from(
    (req.headers.authorization || "").replace(/^Bearer\s+/i, "")
  );
  const want = Buffer.from(token);
  return given.length === want.length && crypto.timingSafeEqual(given, want);
};

// ---------------------------------------------------------------------------
// Route matcher
// ---------------------------------------------------------------------------

/**
 * Match a parameterised route pattern against a URL path.
 *
 * Example: `match("/peers/:key", "/peers/AbC=")` → `{ key: "AbC=" }`
 *
 * @param {string} pattern - Route pattern (e.g. `"/peers/:key"`).
 * @param {string} path    - Request URL path.
 * @returns {object|null} Extracted params, or `null` on no match.
 */
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

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

/**
 * @typedef {object} RouteMap
 * @property {string}   VERSION     - Package version string.
 * @property {string}   dir         - Agent identity directory.
 * @property {object}   stealthState
 * @property {number}   echoPort
 * @property {string[]} [public]    - Route strings that skip bearer auth.
 * @property {Function} [*]         - Route handlers keyed as `"METHOD /path"`.
 */

/**
 * Create and bind the HTTP/HTTPS control-API server.
 *
 * Route handlers receive `(body, params, ctx)` where
 * `ctx = { req, res, url, ip }`.  Returning `undefined` signals that the
 * handler has already written the response (e.g. streaming).
 *
 * @param {{ port: number, token: string, tls: boolean, routes: RouteMap }} opts
 * @returns {"http"|"https"} The scheme actually in use.
 */
function serve({ port, token, tls, routes }) {
  // Pre-compute the set of public route specs so /speedtest etc. don't need a
  // linear scan through the full route map on every request.
  const publicRoutes = routes.public || [];

  /** @param {import("http").IncomingMessage} req */
  const handler = async (req, res) => {
    /** @param {number} status @param {object} obj */
    const send = (status, obj) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(obj));
    };

    try {
      const url  = new URL(req.url, "https://x");
      const path = url.pathname;

      // Health check — unauthenticated, not rate-limited.
      if (req.method === "GET" && path === "/health") {
        return send(200, { ok: true, version: routes.VERSION });
      }

      const ip = req.socket.remoteAddress;
      if (rateLimited(ip)) {
        return send(429, { ok: false, error: "rate limited" });
      }

      // Public routes skip the bearer check.
      const isPublic = publicRoutes.some((r) => {
        const i = r.indexOf(" ");
        return r.slice(0, i) === req.method && match(r.slice(i + 1), path);
      });
      if (!isPublic && !authed(req, token)) {
        return send(401, { ok: false, error: "unauthorized" });
      }

      // Dispatch to a registered route handler.
      for (const [route, fn] of Object.entries(routes)) {
        if (!route.includes(" ")) continue; // skip VERSION/dir/public meta keys
        const [method, pattern] = route.split(" ");
        if (method !== req.method) continue;
        const params = match(pattern, path);
        if (!params) continue;
        const body = method === "POST" ? await readBody(req) : {};
        const data = await fn(body, params, { req, res, url, ip });
        if (data === undefined) return; // route wrote the response itself (streaming)
        return send(200, { ok: true, data });
      }

      return send(404, { ok: false, error: "not found" });
    } catch (e) {
      if (res.headersSent) return res.end(); // mid-stream failure
      return send(e.status || 500, { ok: false, error: e.message || String(e) });
    }
  };

  const srv = tls
    ? https.createServer(
        { cert: identity.cert(routes.dir), key: identity.key(routes.dir) },
        handler
      )
    : http.createServer(handler);

  srv.listen(port, "0.0.0.0");
  return tls ? "https" : "http";
}

module.exports = { serve };
