// Wpn node agent — orchestrator.
//
//   wpn-agent             → preflight, bootstrap WireGuard, serve control API
//   wpn-agent --print     → re-print Agent URL + key
//   wpn-agent --install   → copy to /opt + systemd unit + start
//   wpn-agent --uninstall → remove the service
//   wpn-agent --skip-wg   → API only, don't touch WireGuard (dev smoke)

const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { isRoot, log } = require("./util");
const preflight = require("./preflight");
const wg = require("./wireguard");
const identity = require("./identity");
const server = require("./server");
const service = require("./service");
const stealth = require("./stealth");
const echo = require("./echo");

const VERSION = require("../package.json").version;

const AGENT_PORT = parseInt(process.env.WPN_AGENT_PORT || "44664", 10);
const WG_PORT = parseInt(process.env.WPN_WG_PORT || "51820", 10);
const DIR = process.env.WPN_AGENT_DIR || "/etc/wpn-agent";
// populated in main() after DIR exists; capabilities/info read it
let STEALTH = { enabled: false };

const err = (status, message) => Object.assign(new Error(message), { status });

// /speedtest — public bandwidth probe, hard-capped so it can't be abused as
// an amplifier: 4 requests/minute per IP, max 8MB per request.
const SPEED_LIMIT = 4;
const SPEED_DEF = 2 * 1024 * 1024;
const SPEED_MAX = 8 * 1024 * 1024;
const speedHits = new Map(); // ip -> {count, reset}

function speedLimited(ip) {
  const now = Date.now();
  const e = speedHits.get(ip);
  if (!e || now > e.reset) {
    speedHits.set(ip, { count: 1, reset: now + 60000 });
  } else if (++e.count > SPEED_LIMIT) {
    return true;
  }
  if (speedHits.size > 4096) {
    // lazy sweep — keep the map bounded on busy hosts
    for (const [k, v] of speedHits) if (now > v.reset) speedHits.delete(k);
  }
  return false;
}

function banner(token, scheme) {
  const ip = preflight.publicIp() || "0.0.0.0";
  const pub = wg.serverPubKey(identity.pubFile(DIR)) || "(none)";
  const live = wg.liveInfo();
  const wgPort = live.listenPort || WG_PORT;
  console.log(
    [
      "",
      "════════════════════════════════════════════════════════════",
      " Wpn node agent is live",
      `   Agent URL:      ${scheme}://${ip}:${AGENT_PORT}`,
      `   Agent key:      ${token}`,
      `   Server pubkey:  ${pub}`,
      `   WG endpoint:    ${ip}:${wgPort}/udp`,
      "════════════════════════════════════════════════════════════",
      " Add it:  Wpn Admin → Servers → label + URL + key.",
      " Note:    open udp/" + wgPort + " and tcp/" + AGENT_PORT + " in your cloud firewall.",
      " Reprint: wpn-agent --print     Service: wpn-agent --install",
      "",
    ].join("\n")
  );
}

function routes() {
  return {
    VERSION,
    dir: DIR,
    stealthState: STEALTH,
    echoPort: echo.port(),
    public: ["GET /speedtest"],
    "GET /speedtest": async (_b, _p, { req, res, url, ip }) => {
      if (speedLimited(ip)) throw err(429, "speedtest rate limited");
      let n = parseInt(url.searchParams.get("bytes") || "", 10);
      if (!Number.isFinite(n) || n <= 0) n = SPEED_DEF;
      n = Math.min(n, SPEED_MAX);
      res.writeHead(200, {
        "content-type": "application/octet-stream",
        "content-length": n,
        "cache-control": "no-store",
      });
      let sent = 0;
      while (sent < n) {
        if (res.destroyed || req.destroyed) return undefined; // client gone
        const chunk = crypto.randomBytes(Math.min(65536, n - sent));
        sent += chunk.length;
        if (!res.write(chunk)) {
          await new Promise((r) => res.once("drain", r));
        }
      }
      res.end();
      return undefined; // response already streamed
    },
    "GET /info": async () => {
      const live = wg.liveInfo();
      return {
        version: VERSION,
        publicKey: wg.serverPubKey(identity.pubFile(DIR)),
        endpoint: `${preflight.publicIp()}:${live.listenPort || WG_PORT}`,
        subnet: live.subnet || "10.66.0.0/24",
        hostname: os.hostname(),
        uptime: os.uptime(),
        // authed route only — the key never leaves the public surface
        stealth: STEALTH.enabled
          ? { enabled: true, port: STEALTH.port, key: STEALTH.key }
          : { enabled: false },
      };
    },
    "GET /stats": async () => ({
      ...wg.stats(),
      version: VERSION,
      hostname: os.hostname(),
      uptime: os.uptime(),
      cpuCount: os.cpus().length,
      memTotal: os.totalmem(),
      memFree: os.freemem(),
      wgVersion: wg.version(),
      iface: wg.WG_IFACE,
    }),
    "GET /peers": async () => wg.dump().peers,
    "POST /peers": async (body) => wg.addPeer(body.publicKey, body.address),
    "DELETE /peers/:key": async (_b, p) => wg.removePeer(p.key),
    "GET /capabilities": async () => ({
      stealth: STEALTH.enabled,
      stealthPort: STEALTH.port ?? null,
      stealthMode: STEALTH.enabled ? "wss" : null,
      stealthError: STEALTH.error ?? undefined,
      echoPort: echo.port(),
      streaming: false,
      version: VERSION,
      wgVersion: wg.version(),
    }),
    // POST /update — fast-forward the checkout and restart the service.
    // Responds BEFORE the restart; the old agent still answers the call.
    "POST /update": async () => {
      if (!fs.existsSync(path.join(DIR, ".git"))) {
        throw err(409, "agent directory is not a git checkout — update manually");
      }
      let output = "";
      try {
        output = require("child_process")
          .execFileSync("git", ["-C", DIR, "pull", "--ff-only"], {
            timeout: 60000,
            encoding: "utf8",
          })
          .trim();
      } catch (e) {
        throw err(502, `git pull failed: ${e.message.slice(0, 300)}`);
      }
      // restart only where systemd actually runs this service
      if (process.platform === "linux") {
        setTimeout(() => {
          require("child_process")
            .exec("systemctl restart wpn-agent", () => {});
        }, 1000).unref();
      }
      return { ok: true, from: VERSION, output };
    },
  };
}

async function main() {
  const args = process.argv.slice(2);
  const skipWg = args.includes("--skip-wg");

  if (!isRoot() && !skipWg) {
    log.err("run as root — the agent manages WireGuard");
    process.exit(1);
  }

  if (args.includes("--uninstall")) return service.uninstall();

  if (!skipWg) {
    const report = preflight.collect({ agentPort: AGENT_PORT, wgPort: WG_PORT });
    preflight.report(report);
    if (!report.ports.agentTcp.free) {
      log.warn(`tcp/${AGENT_PORT} is already bound — set WPN_AGENT_PORT to change it`);
    }
    wg.ensure(report, { wgPort: WG_PORT, agentPort: AGENT_PORT });
  }

  const { tls } = identity.ensure(DIR);
  if (!tls) log.warn("openssl unavailable — agent will serve plain HTTP");

  // publish the server pubkey where /info can read it
  try {
    const pub = wg.serverPubKey(identity.pubFile(DIR));
    if (pub) fs.writeFileSync(identity.pubFile(DIR), pub + "\n", { mode: 0o644 });
  } catch {}
  const token = identity.token(DIR);

  if (args.includes("--print")) {
    return banner(token, tls ? "https" : "http");
  }
  if (args.includes("--install")) {
    return service.install(AGENT_PORT);
  }

  // UDP echo reflector for the client's loss/jitter probe
  echo.start();

  // Stealth relay — optional; failures degrade to stealth:false, never fatal.
  STEALTH = await stealth.ensure(DIR, { wgPort: WG_PORT });
  if (STEALTH.enabled) log.ok(`stealth relay on tcp/${STEALTH.port} (wss)`);
  else if (STEALTH.error) log.warn(`stealth unavailable: ${STEALTH.error}`);

  const scheme = server.serve({ port: AGENT_PORT, token, tls, routes: routes() });
  banner(token, scheme);
  log.ok(`control API listening on :${AGENT_PORT} (${scheme})`);
}

module.exports = { main };
