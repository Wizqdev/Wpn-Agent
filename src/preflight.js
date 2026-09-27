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

/** @type {string|null|undefined} `undefined` means not yet fetched. */
let _publicIp;

/**
 * Probe the host's public IPv4 address.  Result is memoised for the lifetime
 * of the process — the IP never changes while the agent is running.
 *
 * @returns {string|null}
 */
const publicIp = () => {
  if (_publicIp !== undefined) return _publicIp;
  _publicIp =
    tryRun("curl -s4 --max-time 5 ifconfig.me") ||
    tryRun("curl -s4 --max-time 5 icanhazip.com") ||
    tryRun("hostname -I | awk '{print $1}'") ||
    null;
  return _publicIp;
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
function collect({ agentPort, wgPort }) {
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
    ipv4:     publicIp(),
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
    wgUp: (tryRun("wg show interfaces") || "").split(/\s+/).includes("wg0"),
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
