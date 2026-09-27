/**
 * @fileoverview Control API HTTP/HTTPS server with graceful shutdown.
 *
 * In-flight request tracking ensures that on `SIGTERM` the server stops
 * accepting new connections but lets active requests drain before the process
 * exits.  The drain timeout is {@link DRAIN_TIMEOUT_MS} (10 seconds).
 *
 * Route handlers receive `(body, params, ctx)` where
 * `ctx = { req, res, url, ip }`.  Returning `undefined` signals that the
 * handler has already written the response (streaming).
 */

"use strict";

const http   = require("http");
const https  = require("https");
const crypto = require("crypto");
const identity = require("./identity");

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

const RATE_LIMIT    = 120;      // authed requests / minute / IP
const RATE_SWEEP_AT = 4_096;    // sweep map when it exceeds this many entries

/** @type {Map<string, {count: number, reset: number}>} */
const hits = new Map();

/**
 * @param {string} ip
 * @returns {boolean} `true` if this IP has exceeded the rate limit.
 */
function rateLimited(ip) {
  const now = Date.now();
  const e   = hits.get(ip);
  if (!e || now > e.reset) {
    hits.set(ip, { count: 1, reset: now + 60_000 });
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
 * @param {number} status
 * @param {string} message
 * @returns {Error & {status: number}}
 */
const err = (status, message) => Object.assign(new Error(message), { status });

/**
 * Buffer the full request body and parse as JSON.  Destroys the socket if
 * the body exceeds 64 KiB.
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
 * @param {string} pattern - e.g. `"/peers/:key"`
 * @param {string} path    - Request URL path
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
// Graceful shutdown
// ---------------------------------------------------------------------------

/** Maximum time (ms) to wait for in-flight requests to drain on SIGTERM. */
const DRAIN_TIMEOUT_MS = 10_000;

/** Counter of currently active requests. */
let _inFlight = 0;

/** Set to `true` once the server begins shutting down. */
let _draining = false;

/** Resolves when in-flight count drops to zero during drain. */
let _drainResolve = null;

/**
 * Initiate graceful shutdown.  Stops accepting new connections and waits up to
 * {@link DRAIN_TIMEOUT_MS} for in-flight requests to complete.
 *
 * @param {import("http").Server|import("https").Server} srv
 * @returns {Promise<void>}
 */
function gracefulShutdown(srv) {
  _draining = true;
  return new Promise((resolve) => {
    srv.close(() => resolve()); // stop accepting new connections
    if (_inFlight === 0) return resolve();
    _drainResolve = resolve;
    setTimeout(() => resolve(), DRAIN_TIMEOUT_MS).unref();
  });
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

/**
 * @typedef {object} RouteMap
 * @property {string}   VERSION
 * @property {string}   dir
 * @property {object}   stealthState
 * @property {number}   echoPort
 * @property {string[]} [public]    Route strings that skip bearer auth.
 * @property {Function} [*]         Route handlers keyed as `"METHOD /path"`.
 */

/**
 * @typedef {{ shutdown: () => Promise<void> }} ServerHandle
 */

/**
 * Create and bind the HTTP/HTTPS control-API server.
 *
 * @param {{ port: number, token: string, tls: boolean, routes: RouteMap,
 *           health?: import('./health') }} opts
 * @returns {{ scheme: "http"|"https", shutdown: () => Promise<void> }}
 */
function serve({ port, token, tls, routes, health }) {
  const publicRoutes = routes.public || [];

  /** @param {import("http").IncomingMessage} req */
  const handler = async (req, res) => {
    if (_draining) {
      res.writeHead(503, { "content-type": "application/json", "connection": "close" });
      res.end(JSON.stringify({ ok: false, error: "server shutting down" }));
      return;
    }

    _inFlight++;
    res.on("finish", () => {
      _inFlight--;
      if (_draining && _inFlight === 0 && _drainResolve) _drainResolve();
    });
    res.on("close", () => {
      // also decrement on aborted connections
      if (res.writableEnded) return; // already counted by finish
      _inFlight--;
      if (_draining && _inFlight === 0 && _drainResolve) _drainResolve();
    });

    /** @param {number} status @param {object} obj */
    const send = (status, obj) => {
      if (res.headersSent) return;
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(obj));
    };

    try {
      const url  = new URL(req.url, "https://x");
      const path = url.pathname;

      // Health check — unauthenticated, not rate-limited.
      // Surfaces wg0 health so load balancers get an accurate signal.
      if (req.method === "GET" && path === "/health") {
        const wgHealth = health ? health.status() : null;
        const isHealthy = !wgHealth || wgHealth.up;
        return send(isHealthy ? 200 : 503, {
          ok:      isHealthy,
          version: routes.VERSION,
          ...(wgHealth ? { wg: wgHealth } : {}),
        });
      }

      const ip = req.socket.remoteAddress;
      if (rateLimited(ip)) {
        return send(429, { ok: false, error: "rate limited" });
      }

      const isPublic = publicRoutes.some((r) => {
        const i = r.indexOf(" ");
        return r.slice(0, i) === req.method && match(r.slice(i + 1), path);
      });
      if (!isPublic && !authed(req, token)) {
        return send(401, { ok: false, error: "unauthorized" });
      }

      for (const [route, fn] of Object.entries(routes)) {
        if (!route.includes(" ")) continue;
        const [method, pattern] = route.split(" ");
        if (method !== req.method) continue;
        const params = match(pattern, path);
        if (!params) continue;
        const body = method === "POST" ? await readBody(req) : {};
        const data = await fn(body, params, { req, res, url, ip });
        if (data === undefined) return;
        return send(200, { ok: true, data });
      }

      return send(404, { ok: false, error: "not found" });
    } catch (e) {
      if (res.headersSent) return res.end();
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
  const scheme = tls ? "https" : "http";

  return {
    scheme,
    shutdown: () => gracefulShutdown(srv),
  };
}

module.exports = { serve, match, rateLimited };
