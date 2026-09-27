/**
 * @fileoverview Preflight — inspect the host machine before doing any work and
 * print a human-readable summary.  The operator can read this output and
 * sanity-check the box before changes are applied.
 *
 * `publicIp()` is memoised: the first caller (collect) pays the cost of two
 * potential HTTP round-trips; all subsequent callers get the cached value
 * instantly.
 */

"use strict";

const os = require("os");
const fs = require("fs");
const https = require("https");
const { tryRun } = require("./util");

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Parse `/etc/os-release` for a human-friendly distro description.
 *
 * @returns {{ id: string, pretty: string }}
 */
const osRelease = () => {
  try {
    const raw = fs.readFileSync("/etc/os-release", "utf8");
    const get = (k) =>
      (raw.match(new RegExp(`^${k}="?([^"\\n]+)"?`, "m")) || [])[1];
    return { id: get("ID") || "linux", pretty: get("PRETTY_NAME") || "Linux" };
  } catch {
    return { id: "linux", pretty: "Linux" };
  }
};

/**
 * Detect the first available package manager from a priority-ordered list.
 *
 * @returns {string|null}
 */
const detectPkgMgr = () => {
  for (const m of ["apt-get", "dnf", "yum", "pacman", "zypper"]) {
    if (tryRun(`command -v ${m}`)) return m;
  }
  return null;
};

// ---------------------------------------------------------------------------
// Public IP — memoised so collect() and banner() share one HTTP round-trip.
// ---------------------------------------------------------------------------

/** @type {Promise<string|null>|undefined} */
let _publicIpPromise;

/**
 * Check if an IPv4 address is in RFC1918 or RFC6598 private space.
 * @param {string} ip
 * @returns {boolean}
 */
const isPrivateIp = (ip) => {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4) return false;
  if (parts[0] === 10) return true;
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  if (parts[0] === 192 && parts[1] === 168) return true;
  if (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127) return true;
  return false;
};

/**
 * Fetch public IP using native Node.js https.
 * @returns {Promise<string|null>}
 */
const fetchExternalIp = () =>
  new Promise((resolve) => {
    const req = https.get("https://ifconfig.me", { timeout: 3000 }, (res) => {
      if (res.statusCode !== 200) return resolve(null);
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => resolve(data.trim() || null));
    });
    req.on("error", () => resolve(null));
    req.on("timeout", () => {
      req.destroy();
      resolve(null);
    });
  });

/**
 * Determine the host's public IPv4 address.
 * 1. Inspects the active default route interface. If its IP is public, use it.
 * 2. If it's a private IP (NATed, like EC2/GCP), queries via HTTPS natively.
 * Memoised for the lifetime of the process.
 *
 * @returns {Promise<string|null>}
 */
const publicIp = async () => {
  if (_publicIpPromise !== undefined) return _publicIpPromise;

  _publicIpPromise = (async () => {
    const localIp = tryRun("ip -4 route get 8.8.8.8 | grep -oP 'src \\K\\S+'");
    if (localIp && !isPrivateIp(localIp)) return localIp;
    
    const extIp = await fetchExternalIp();
    if (extIp) return extIp;

    return localIp || null; // fallback to whatever local IP we found
  })();

  return _publicIpPromise;
};

/**
 * Check whether a port appears free using `ss`.
 *
 * @param {number} port
 * @param {"tcp"|"udp"} proto
 * @returns {boolean} `true` if the port is free (or `ss` is not available).
 */
const portFree = (port, proto) => {
  const flag = proto === "udp" ? "-lun" : "-ltn";
  const out = tryRun(`ss ${flag} 2>/dev/null | grep -c ':${port} '`);
  return out === "0" || out === null; // null → ss missing; assume free
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Collect a full machine snapshot used by the WireGuard bootstrap and the
 * preflight report.
 *
 * @param {{ agentPort: number, wgPort: number }} opts
 * @returns {object} Machine report object.
 */
async function collect({ agentPort, wgPort }) {
  const osr   = osRelease();
  const wgVer = tryRun("wg --version | awk '{print $2}'");
  const fwd4  = tryRun("sysctl -n net.ipv4.ip_forward 2>/dev/null") === "1";
  const fwd6  = tryRun("sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null") === "1";

  return {
    os:       osr,
    kernel:   os.release(),
    arch:     os.arch(),
    hostname: os.hostname(),
    node:     process.version,
    ipv4:     await publicIp(),
    wanIf:
      tryRun("ip route show default | awk '/default/ {print $5; exit}'") ||
      "eth0",
    pkgMgr:  detectPkgMgr(),
    systemd: !!tryRun("systemctl --version"),
    ufw:     !!tryRun("command -v ufw"),
    wg:      { installed: !!wgVer, version: wgVer },
    forwarding: { ipv4: fwd4, ipv6: fwd6 },
    ports: {
      agentTcp: { port: agentPort, free: portFree(agentPort, "tcp") },
      wgUdp:    { port: wgPort,    free: portFree(wgPort,    "udp") },
    },
    wgUp: (tryRun("wg show interfaces") || "").split(/\s+/).includes(process.env.WPN_WG_IFACE || "wg0"),
  };
}

// ---------------------------------------------------------------------------
// Console report
// ---------------------------------------------------------------------------

/**
 * @param {string} k - Left-column label.
 * @param {string|boolean} v - Value; booleans are rendered as yes/no.
 */
const row = (k, v) =>
  process.stdout.write(
    `   ${k.padEnd(18)} ${typeof v === "boolean" ? (v ? "yes" : "no") : v}\n`
  );

/**
 * Print the preflight report to stdout.
 *
 * @param {ReturnType<typeof collect>} r
 */
function report(r) {
  process.stdout.write("\n──────────────── machine ────────────────\n");
  row("os",           `${r.os.pretty} (${r.os.id})`);
  row("kernel/arch",  `${r.kernel} / ${r.arch}`);
  row("hostname",     r.hostname);
  row("node",         r.node);
  row("public ipv4",  r.ipv4 || "unknown");
  row("wan iface",    r.wanIf);
  row("pkg manager",  r.pkgMgr || "none found");
  row("systemd",      r.systemd);
  row("ufw",          r.ufw);
  process.stdout.write("──────────────── wireguard ──────────────\n");
  row("wg installed", r.wg.installed ? r.wg.version : "no — will install");
  row("wg0 up",       r.wgUp);
  row("ip_forward v4", r.forwarding.ipv4);
  row("ip_forward v6", r.forwarding.ipv6);
  process.stdout.write("──────────────── ports ───────────────────\n");
  row(`tcp/${r.ports.agentTcp.port}`, r.ports.agentTcp.free ? "free" : "TAKEN!");
  row(`udp/${r.ports.wgUdp.port}`,   r.ports.wgUdp.free    ? "free" : "taken");
  process.stdout.write("─────────────────────────────────────────\n\n");
}

module.exports = { collect, report, publicIp };
