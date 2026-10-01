
"use strict";

const http   = require("http");
const https  = require("https");
const crypto = require("crypto");
const identity = require("./identity");
const { err, log, rateLimiter } = require("./util");

const RATE_LIMIT    = 120;
const RATE_SWEEP_AT = 4_096;

const rateLimited = rateLimiter({ limit: RATE_LIMIT, sweepAt: RATE_SWEEP_AT });

const MAX_BODY_BYTES = 64 * 1_024;

const BODY_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

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
      bytes += buf.length;
      if (bytes > MAX_BODY_BYTES) return fail(err(413, "body too large"));
      chunks.push(buf);
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

const authed = (req, token) => {

  const m = (req.headers.authorization || "").match(/^Bearer\s+(\S+)\s*$/i);
  if (!m) return false;
  const given = Buffer.from(m[1]);
  const want  = Buffer.from(token);
  return given.length === want.length && crypto.timingSafeEqual(given, want);
};


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
        return null;
      }
    } else if (pp[i] !== ap[i]) return null;
  }
  return params;
}

const DRAIN_TIMEOUT_MS = 10_000;

let _inFlight = 0;

let _draining = false;

let _drainResolve = null;

function gracefulShutdown(srv) {
  _draining = true;
  return new Promise((resolve) => {
    srv.close(() => resolve());
    if (_inFlight === 0) return resolve();
    _drainResolve = resolve;
    setTimeout(() => resolve(), DRAIN_TIMEOUT_MS).unref();
  });
}

function serve({ port, token, tls, routes, health }) {
  const publicRoutes = routes.public || [];

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

      if (res.writableEnded) return;
      _inFlight--;
      if (_draining && _inFlight === 0 && _drainResolve) _drainResolve();
    });

        const send = (status, obj) => {
      if (res.headersSent) return;
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(obj));
    };

    try {
      const url  = new URL(req.url, "https://x");
      const path = url.pathname;

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

  srv.headersTimeout = 20_000;

  srv.on("error", (e) => {
    log.err(`control API failed to bind tcp/${port} — ${e.message}`);
    process.exit(1);
  });

  srv.listen(port, "0.0.0.0");
  const scheme = tls ? "https" : "http";

  return {
    scheme,
    shutdown: () => gracefulShutdown(srv),
  };
}

module.exports = { serve, match, rateLimited, authed, readBody, MAX_BODY_BYTES };
