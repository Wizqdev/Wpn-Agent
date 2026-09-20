// Wpn node agent — orchestrator.
//
//   wpn-agent             → preflight, bootstrap WireGuard, serve control API
//   wpn-agent --print     → re-print Agent URL + key
//   wpn-agent --install   → copy to /opt + systemd unit + start
//   wpn-agent --uninstall → remove the service
//   wpn-agent --skip-wg   → API only, don't touch WireGuard (dev smoke)

const fs = require("fs");
const os = require("os");
const path = require("path");
const { isRoot, log } = require("./util");
const preflight = require("./preflight");
const wg = require("./wireguard");
const identity = require("./identity");
const server = require("./server");
const service = require("./service");

const VERSION = require("../package.json").version;

const AGENT_PORT = parseInt(process.env.WPN_AGENT_PORT || "44664", 10);
const WG_PORT = parseInt(process.env.WPN_WG_PORT || "51820", 10);
const DIR = process.env.WPN_AGENT_DIR || "/etc/wpn-agent";

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
    "GET /info": async () => {
      const live = wg.liveInfo();
      return {
        version: VERSION,
        publicKey: wg.serverPubKey(identity.pubFile(DIR)),
        endpoint: `${preflight.publicIp()}:${live.listenPort || WG_PORT}`,
        subnet: live.subnet || "10.66.0.0/24",
        hostname: os.hostname(),
        uptime: os.uptime(),
      };
    },
    "GET /stats": async () => ({
      ...wg.stats(),
      version: VERSION,
      hostname: os.hostname(),
      uptime: os.uptime(),
    }),
    "GET /peers": async () => wg.dump().peers,
    "POST /peers": async (body) => wg.addPeer(body.publicKey, body.address),
    "DELETE /peers/:key": async (_b, p) => wg.removePeer(p.key),
  };
}

function main() {
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

  const scheme = server.serve({ port: AGENT_PORT, token, tls, routes: routes() });
  banner(token, scheme);
  log.ok(`control API listening on :${AGENT_PORT} (${scheme})`);
}

module.exports = { main };
