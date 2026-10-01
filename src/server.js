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
const { err, log, rateLimiter } = require("./util");

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

const RATE_LIMIT    = 120;      // authed requests / minute / IP
const RATE_SWEEP_AT = 4_096;    // sweep map when it exceeds this many entries

/** `true` when the IP has exceeded the authenticated rate limit. */
const rateLimited = rateLimiter({ limit: RATE_LIMIT, sweepAt: RATE_SWEEP_AT });

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Maximum request-body size, in bytes. */
const MAX_BODY_BYTES = 64 * 1_024;

/** Methods that may carry a JSON body. */
const BODY_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

/**
 * Buffer the full request body and parse as JSON.  Rejects with a 413 when
 * the body exceeds 64 KiB (socket is destroyed) and a 400 on bad JSON.
 *
 * @param {import("http").IncomingMessage} req
 * @returns {Promise<object>}
 */
const readBody = (req) =>
  new Promise((resolve, reject) => {
    const chunks = [];
    let bytes = 0;
    let done = false;
    const fail = (e) => {
      if (done) return;
      done = true;
      req.destroy();
      reject(e);
    };
    req.on("data", (c) => {
      if (done) return;
      const buf = Buffer.isBuffer(c) ? c : Buffer.from(c);
      bytes += buf.length; // true bytes, not UTF-16 units
      if (bytes > MAX_BODY_BYTES) return fail(err(413, "body too large"));
      chunks.push(buf); // decode once at the end — a multi-byte char may span chunks
    });
    req.on("end", () => {
      if (done) return;
      done = true;
      try {
        const data = Buffer.concat(chunks).toString("utf8");
        resolve(data ? JSON.parse(data) : {});
      } catch {
        reject(err(400, "bad JSON"));
      }
    });
    req.on("error", () => fail(err(400, "request error")));
    req.on("close", () => fail(err(400, "connection closed")));
  });

/**
 * Constant-time bearer token comparison.
 *
 * @param {import("http").IncomingMessage} req
 * @param {string} token
 * @returns {boolean}
 */
const authed = (req, token) => {
  // Strict "Bearer <token>" — a bare token without the scheme is rejected.
  const m = (req.headers.authorization || "").match(/^Bearer\s+(\S+)\s*$/i);
  if (!m) return false;
  const given = Buffer.from(m[1]);
  const want  = Buffer.from(token);
  return given.length === want.length && crypto.timingSafeEqual(given, want);
};

// ---------------------------------------------------------------------------
// Route matcher
// ---------------------------------------------------------------------------

/**
 * Match a parameterised route pattern against a URL path.
 *
 * @param {string} pattern - e.g. `"/peers/:key"`
 * @param {string} path    - Request URL path (still percent-encoded).
 * @returns {object|null} Extracted params, or `null` on no match / malformed
 *   percent-encoding.  Encoded slashes (`%2F`) decode into the param, which
 *   is how base64 WireGuard keys containing `/` are transported.
 */
function match(pattern, path) {
  const pp = pattern.split("/");
  const ap = path.split("/");
  if (pp.length !== ap.length) return null;
  const params = {};
  for (let i = 0; i < pp.length; i++) {
    if (pp[i].startsWith(":")) {
      try {
        params[pp[i].slice(1)] = decodeURIComponent(ap[i]);
      } catch {
        return null; // malformed percent-encoding
      }
    } else if (pp[i] !== ap[i]) return null;
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
 * @typedef {{ scheme: "http"|"https", shutdown: () => Promise<void> }} ServerHandle
 */

/**
 * Create and bind the HTTP/HTTPS control-API server.
 *
 * @param {{ port: number, token: string, tls: boolean, routes: RouteMap,
 *           health?: import('./health') }} opts
 * @returns {ServerHandle}
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
        log.warn(`auth failure from ${ip} on ${req.method} ${path}`);
        return send(401, { ok: false, error: "unauthorized" });
      }

      for (const [route, fn] of Object.entries(routes)) {
        if (!route.includes(" ")) continue;
        const [method, pattern] = route.split(" ");
        if (method !== req.method) continue;
        const params = match(pattern, path);
        if (!params) continue;
        const body = BODY_METHODS.has(method) ? await readBody(req) : {};
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

  // Slowloris hardening — headers must complete promptly.  (requestTimeout
  // stays at the Node default so long speedtest streams are not cut off.)
  srv.headersTimeout = 20_000;

  srv.on("error", (e) => {
    log.err(`control API failed to bind tcp/${port} — ${e.message}`);
    process.exit(1); // systemd Restart=always will retry with a clean state
  });

  srv.listen(port, "0.0.0.0");
  const scheme = tls ? "https" : "http";

  return {
    scheme,
    shutdown: () => gracefulShutdown(srv),
  };
}

module.exports = { serve, match, rateLimited, authed, readBody, MAX_BODY_BYTES };
