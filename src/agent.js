/**
 * @fileoverview Wpn node agent — top-level orchestrator.
 *
 * Handles graceful shutdown on SIGTERM/SIGINT, global error boundaries,
 * and ties together preflight, WireGuard bootstrap, and the API server.
 *
 * Command paths:
 *  - `--print` / `--install` / `--uninstall` are operational commands and exit
 *    BEFORE the WireGuard bootstrap — printing the agent key must not mutate
 *    the host (install packages, rewrite sysctl, bring up interfaces).
 *  - bare run / `--skip-wg` → preflight → bootstrap → serve the control API.
 */

"use strict";

const crypto         = require("crypto");
const fs             = require("fs");
const os             = require("os");
const path           = require("path");
const { isRoot, log, runBin, err, rateLimiter } = require("./util");
const preflight      = require("./preflight");
const wg             = require("./wireguard");
const identity       = require("./identity");
const server         = require("./server");
const service        = require("./service");
const stealth        = require("./stealth");
const echo           = require("./echo");
const health         = require("./health");

const VERSION = require("../package.json").version;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const AGENT_PORT = parseInt(process.env.WPN_AGENT_PORT || "44664", 10);
const WG_PORT    = parseInt(process.env.WPN_WG_PORT    || "51820", 10);
const DIR        = process.env.WPN_AGENT_DIR || "/etc/wpn-agent";

/** Directory the agent code actually runs from — used by `POST /update`. */
const APP_DIR = path.resolve(__dirname, "..");

let STEALTH = { enabled: false };

// ---------------------------------------------------------------------------
// Global error boundaries
// ---------------------------------------------------------------------------

process.on("uncaughtException", (err) => {
  log.err("uncaught exception", { error: err.stack || err.message });
  process.exit(1);
});

process.on("unhandledRejection", (reason) => {
  log.err("unhandled rejection", { error: reason instanceof Error ? reason.stack : reason });
  process.exit(1);
});

// ---------------------------------------------------------------------------
// Speedtest
// ---------------------------------------------------------------------------

const SPEED_LIMIT = 4;
const SPEED_DEF   = 2 * 1_024 * 1_024;
const SPEED_MAX   = 8 * 1_024 * 1_024;
const SPEED_CHUNK = 65_536;

/** `true` when the IP has exceeded the speedtest rate limit. */
const speedLimited = rateLimiter({ limit: SPEED_LIMIT });

/**
 * Payload source for /speedtest.  Filled once with random bytes and reused —
 * CSPRNG per chunk would burn CPU for zero benefit; the bytes just need to be
 * non-zero and non-constant so compression can't cheat the measurement.
 */
let _speedPayload = null;
const speedPayload = () => (_speedPayload ||= crypto.randomBytes(SPEED_CHUNK));

// ---------------------------------------------------------------------------
// Banner
// ---------------------------------------------------------------------------

/**
 * Print the operator banner.  The bearer token is only revealed on an
 * interactive TTY (`--print`, manual run); under systemd/journald it is
 * redacted so the API secret is not persisted in `journalctl` for anyone
 * with journal read access.
 *
 * @param {string}      token
 * @param {string}      scheme    - "https" | "http"
 * @param {string|null} cachedIp
 * @param {{ forceReveal?: boolean }} [opts]
 */
async function banner(token, scheme, cachedIp, opts = {}) {
  const ip        = cachedIp || (await preflight.publicIp()) || "0.0.0.0";
  const pub       = (await wg.serverPubKey(identity.pubFile(DIR))) || "(none)";
  const live      = await wg.liveInfo();
  const wgPort    = live.listenPort || WG_PORT;
  const fp        = identity.fingerprint(DIR);
  const reveal    = opts.forceReveal ?? process.stdout.isTTY === true;
  const shownKey  = reveal
    ? token
    : "(hidden in logs — run `wpn-agent --print` as root to reveal)";

  process.stdout.write(
    [
      "",
      "════════════════════════════════════════════════════════════",
      " Wpn node agent is live",
      `   Agent URL:      ${scheme}://${ip}:${AGENT_PORT}`,
      `   Agent key:      ${shownKey}`,
      `   Server pubkey:  ${pub}`,
      `   WG endpoint:    ${ip}:${wgPort}/udp`,
      ...(fp ? [`   TLS sha256:     ${fp}  (pin this in the API)`] : []),
      "════════════════════════════════════════════════════════════",
      " Add it:  Wpn Admin → Servers → label + URL + key.",
      " Note:    open udp/" + wgPort + " and tcp/" + AGENT_PORT + " in your cloud firewall.",
      " Reprint: wpn-agent --print     Service: wpn-agent --install",
      "",
    ].join("\n") + "\n"
  );
}

// ---------------------------------------------------------------------------
// Route table
// ---------------------------------------------------------------------------

function routes() {
  return {
    VERSION,
    dir:          DIR,
    stealthState: STEALTH,
    echoPort:     echo.port(),
    public:       ["GET /speedtest"],

    "GET /speedtest": async (_b, _p, { req, res, url, ip }) => {
      if (speedLimited(ip)) throw err(429, "speedtest rate limited");
      let n = parseInt(url.searchParams.get("bytes") || "", 10);
      if (!Number.isFinite(n) || n <= 0) n = SPEED_DEF;
      n = Math.min(n, SPEED_MAX);
      res.writeHead(200, {
        "content-type":   "application/octet-stream",
        "content-length": n,
        "cache-control":  "no-store",
      });
      const payload = speedPayload();
      let sent = 0;
      while (sent < n) {
        if (res.destroyed || req.destroyed) return undefined;
        const chunk = n - sent >= SPEED_CHUNK ? payload : payload.subarray(0, n - sent);
        sent += chunk.length;
        if (!res.write(chunk)) {
          await new Promise((r) => res.once("drain", r));
        }
      }
      res.end();
      return undefined;
    },

    "GET /info": async () => {
      const live = await wg.liveInfo();
      const ip   = (await preflight.publicIp()) || "0.0.0.0";
      return {
        version:   VERSION,
        publicKey: await wg.serverPubKey(identity.pubFile(DIR)),
        endpoint:  `${ip}:${live.listenPort || WG_PORT}`,
        subnet:    live.subnet || "10.66.0.0/24",
        hostname:  os.hostname(),
        uptime:    os.uptime(),
        tlsFingerprint: identity.fingerprint(DIR),
        stealth:   STEALTH.enabled
          ? { enabled: true, port: STEALTH.port, key: STEALTH.key }
          : { enabled: false },
      };
    },

    "GET /stats": async () => ({
      ...(await wg.stats()),
      version:  VERSION,
      hostname: os.hostname(),
      uptime:   os.uptime(),
      cpuCount: os.cpus().length,
      memTotal: os.totalmem(),
      memFree:  os.freemem(),
      wgVersion: await wg.version(),
      iface:    wg.WG_IFACE,
    }),

    "GET /peers": async () => (await wg.dump()).peers,

    "GET /peers/usage": async () =>
      (await wg.dump()).peers.map((p) => ({
        publicKey:       p.publicKey,
        rx:              p.rx,
        tx:              p.tx,
        latestHandshake: p.latestHandshake,
      })),

    "POST /peers": async (body, _p, { ip }) => {
      const result = await wg.addPeer(body.publicKey, body.address);
      log.info(`peer added by ${ip}`, {
        pubkey: String(body.publicKey).slice(0, 8),
        address: body.address,
      });
      return result;
    },

    "DELETE /peers": async (body, _p, { ip }) => {
      const result = await wg.removePeer(body.publicKey);
      log.info(`peer removed by ${ip}`, { pubkey: String(body.publicKey).slice(0, 8) });
      return result;
    },

    "DELETE /peers/:key": async (_b, p, { ip }) => {
      const result = await wg.removePeer(p.key);
      log.info(`peer removed by ${ip}`, { pubkey: String(p.key).slice(0, 8) });
      return result;
    },

    "GET /capabilities": async () => ({
      stealth:      STEALTH.enabled,
      stealthPort:  STEALTH.port ?? null,
      stealthMode:  STEALTH.enabled ? "wss" : null,
      stealthError: STEALTH.error ?? undefined,
      echoPort:     echo.port(),
      streaming:    false,
      version:      VERSION,
      wgVersion:    await wg.version(),
    }),

    "POST /update": async (_b, _p, { ip }) => {
      // Root code execution from a bearer token is a large blast radius, so
      // remote update is opt-in per node.
      if (process.env.WPN_ALLOW_REMOTE_UPDATE !== "1") {
        log.warn(`remote update refused for ${ip} (WPN_ALLOW_REMOTE_UPDATE is not 1)`);
        throw err(403, "remote update is disabled on this node — set WPN_ALLOW_REMOTE_UPDATE=1 to enable it");
      }
      // The code lives in APP_DIR (e.g. /opt/wpn-agent); DIR only holds
      // identity material.  install.sh deploys `.git` along with the code so
      // fast-forward updates work here.
      if (!fs.existsSync(path.join(APP_DIR, ".git"))) {
        throw err(409, "agent is not a git checkout — update manually");
      }
      const git  = (...args) => runBin("git", ["-C", APP_DIR, ...args], { timeout: 60_000 });
      const head = () => git("rev-parse", "HEAD").catch(() => null);
      const before = await head();

      let output = "";
      try {
        // fetch → (optionally verify) → fast-forward: the signature is checked
        // BEFORE the working tree moves, so a bad commit is never applied.
        await git("fetch");
        if (process.env.WPN_UPDATE_REQUIRE_SIGNED === "1") {
          try {
            await git("verify-commit", "FETCH_HEAD");
          } catch {
            log.warn(`update from ${ip} rejected: FETCH_HEAD is not a verified signed commit`, { before });
            throw err(403, "update rejected: upstream commit has no valid signature");
          }
        }
        output = await git("merge", "--ff-only", "FETCH_HEAD");
      } catch (e) {
        if (e.status) throw e;
        throw err(502, `git update failed: ${String(e.message).slice(0, 300)}`);
      }
      const after = await head();

      if (process.platform === "linux") {
        setTimeout(() => {
          runBin("systemctl", ["restart", "wpn-agent"]).catch(() => {});
        }, 1_000).unref();
      }
      log.info(`agent updated via /update by ${ip}`, { from: VERSION, before, after });
      return { ok: true, from: VERSION, output, before, after };
    },
  };
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

async function main() {
  const args   = process.argv.slice(2);
  const skipWg = args.includes("--skip-wg");

  if (!isRoot() && !skipWg) {
    log.err("run as root — the agent manages WireGuard");
    process.exit(1);
  }

  // ── Operational commands (no bootstrap, no host mutation) ────────────────
  if (args.includes("--uninstall")) return service.uninstall();

  const { tls } = await identity.ensure(DIR);

  // Cache the server pubkey for --print/--install consumers.  Works before
  // wireguard-tools is installed — falls back to pure-JS X25519.
  try {
    const { pub } = await wg.ensureServerKey();
    if (pub) fs.writeFileSync(identity.pubFile(DIR), pub + "\n", { mode: 0o644 });
  } catch (e) {
    log.warn(`server pubkey cache skipped: ${e.message}`);
  }

  const token = identity.token(DIR);

  if (args.includes("--print")) {
    return banner(token, tls ? "https" : "http", null, { forceReveal: true });
  }
  if (args.includes("--install")) return service.install(AGENT_PORT);

  // ── Bootstrap ─────────────────────────────────────────────────────────────
  let stopHealthMonitor = () => {};
  let report;

  if (!skipWg) {
    report = await preflight.collect({ agentPort: AGENT_PORT, wgPort: WG_PORT });
    preflight.report(report);
    if (!report.ports.agentTcp.free) {
      log.warn(`tcp/${AGENT_PORT} is already bound — set WPN_AGENT_PORT to change it`);
    }
    await wg.ensure(report, { wgPort: WG_PORT, agentPort: AGENT_PORT, echoPort: echo.port() });
    stopHealthMonitor = health.start({ wgConf: wg.WG_CONF, wanIf: report.wanIf });
  }

  if (!tls) log.warn("openssl unavailable — agent will serve plain HTTP");

  echo.start();

  STEALTH = await stealth.ensure(DIR, { wgPort: WG_PORT });
  if (STEALTH.enabled)     log.ok(`stealth relay on tcp/${STEALTH.port} (wss)`);
  else if (STEALTH.error)  log.warn(`stealth unavailable: ${STEALTH.error}`);

  const srv = server.serve({ port: AGENT_PORT, token, tls, routes: routes(), health });
  await banner(token, srv.scheme, report?.ipv4);
  log.ok(`control API listening on :${AGENT_PORT} (${srv.scheme})`);

  // Graceful shutdown
  const shutdown = async (signal) => {
    log.info(`received ${signal} — draining requests and shutting down...`);
    stopHealthMonitor();
    echo.stop();
    await srv.shutdown();
    process.exit(0);
  };
  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT",  () => shutdown("SIGINT"));
}

module.exports = { main, _routes: routes };
