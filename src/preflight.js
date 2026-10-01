/**
 * @fileoverview Preflight — inspect the host machine before doing any work and
 * print a human-readable summary.  The operator can read this output and
 * sanity-check the box before changes are applied.
 *
 * `publicIp()` is memoised with a TTL: callers share one resolution, but the
 * value refreshes periodically so a failover/re-IP is eventually reflected in
 * `/info` instead of being stale for the lifetime of the process.
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
 * @returns {Promise<string|null>}
 */
const detectPkgMgr = async () => {
  for (const m of ["apt-get", "dnf", "yum", "pacman", "zypper"]) {
    if (await tryRun(`command -v ${m}`)) return m;
  }
  return null;
};

// ---------------------------------------------------------------------------
// Public IP — memoised with TTL so collect() and banner() share one lookup.
// ---------------------------------------------------------------------------

/** How long a resolved public IP stays cached (ms). */
const PUBLIC_IP_TTL_MS = 10 * 60_000;

/** @type {{ t: number, p: Promise<string|null> }|undefined} */
let _publicIpCache;

/**
 * Check if an IPv4 address is in any non-globally-routable space:
 * RFC1918, RFC6598 CGNAT, loopback, link-local, "this host", benchmark,
 * multicast/reserved.  Anything listed here cannot be the node's real
 * public endpoint.
 * @param {string} ip
 * @returns {boolean}
 */
const isPrivateIp = (ip) => {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
    return false;
  }
  const [a, b] = parts;
  if (a === 0) return true;                            // 0.0.0.0/8   "this" network
  if (a === 10) return true;                           // 10/8        RFC1918
  if (a === 100 && b >= 64 && b <= 127) return true;   // 100.64/10   CGNAT
  if (a === 127) return true;                          // 127/8       loopback
  if (a === 169 && b === 254) return true;             // 169.254/16  link-local
  if (a === 172 && b >= 16 && b <= 31) return true;    // 172.16/12   RFC1918
  if (a === 192 && b === 0) return true;               // 192.0.0/24  IETF assignments
  if (a === 192 && b === 168) return true;             // 192.168/16  RFC1918
  if (a === 198 && (b === 18 || b === 19)) return true;// 198.18/15   benchmarking
  if (a >= 224) return true;                           // 224/4 multicast + 240/4 reserved
  return false;
};

/**
 * Bare-bones IPv4 shape+range check for the external-IP probe response.
 * @param {string} ip
 * @returns {boolean}
 */
const looksLikeIPv4 = (ip) =>
  /^\d{1,3}(\.\d{1,3}){3}$/.test(ip) &&
  ip.split(".").every((o) => parseInt(o, 10) <= 255);

/**
 * Fetch public IP using native Node.js https.  Hits the dedicated `/ip`
 * endpoint (the bare root returns an HTML page for non-curl user agents) and
 * strictly validates that the answer is actually a public IPv4 address —
 * a captive portal or HTML response must never end up in the banner.
 * @returns {Promise<string|null>}
 */
const fetchExternalIp = () =>
  new Promise((resolve) => {
    const req = https.get(
      "https://ifconfig.me/ip",
      { timeout: 3000, headers: { accept: "text/plain" } },
      (res) => {
        if (res.statusCode !== 200) return resolve(null);
        let data = "";
        res.on("data", (chunk) => {
          data += chunk;
          if (data.length > 64) req.destroy(); // an IP is ≤15 chars — bail on junk
        });
        res.on("end", () => {
          const ip = data.trim();
          resolve(looksLikeIPv4(ip) && !isPrivateIp(ip) ? ip : null);
        });
      }
    );
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
 * Memoised with a {@link PUBLIC_IP_TTL_MS} TTL.
 *
 * @returns {Promise<string|null>}
 */
const publicIp = async () => {
  const now = Date.now();
  if (_publicIpCache && now - _publicIpCache.t < PUBLIC_IP_TTL_MS) {
    return _publicIpCache.p;
  }

  _publicIpCache = {
    t: now,
    p: (async () => {
      const localIp = await tryRun("ip -4 route get 8.8.8.8 | grep -oP 'src \\K\\S+'");
      if (localIp && looksLikeIPv4(localIp) && !isPrivateIp(localIp)) return localIp;

      const extIp = await fetchExternalIp();
      if (extIp) return extIp;

      return looksLikeIPv4(localIp || "") ? localIp : null; // last resort: any valid local addr
    })(),
  };

  return _publicIpCache.p;
};

/**
 * Check whether a port appears free using `ss`.
 *
 * @param {number} port
 * @param {"tcp"|"udp"} proto
 * @returns {Promise<boolean>} `true` if the port is free (or `ss` is unavailable).
 */
const portFree = async (port, proto) => {
  const flag = proto === "udp" ? "-lun" : "-ltn";
  const out = await tryRun(`ss ${flag} 2>/dev/null | grep -c ':${port} '`);
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
 * @returns {Promise<object>} Machine report object.
 */
async function collect({ agentPort, wgPort }) {
  const osr   = osRelease();
  const wgVer = await tryRun("wg --version | awk '{print $2}'");
  const fwd4  = (await tryRun("sysctl -n net.ipv4.ip_forward 2>/dev/null")) === "1";
  const fwd6  = (await tryRun("sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null")) === "1";

  const [ipv4, wanIf, pkgMgr, systemd, ufw, agentFree, wgFree, ifaces] =
    await Promise.all([
      publicIp(),
      tryRun("ip route show default | awk '/default/ {print $5; exit}'"),
      detectPkgMgr(),
      tryRun("systemctl --version"),
      tryRun("command -v ufw"),
      portFree(agentPort, "tcp"),
      portFree(wgPort, "udp"),
      tryRun("wg show interfaces"),
    ]);

  return {
    os:       osr,
    kernel:   os.release(),
    arch:     os.arch(),
    hostname: os.hostname(),
    node:     process.version,
    ipv4,
    wanIf:    wanIf || "eth0",
    pkgMgr,
    systemd: !!systemd,
    ufw:     !!ufw,
    wg:      { installed: !!wgVer, version: wgVer },
    forwarding: { ipv4: fwd4, ipv6: fwd6 },
    ports: {
      agentTcp: { port: agentPort, free: agentFree },
      wgUdp:    { port: wgPort,    free: wgFree },
    },
    wgUp: (ifaces || "")
      .split(/\s+/)
      .includes(process.env.WPN_WG_IFACE || "wg0"),
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
 * @param {Awaited<ReturnType<typeof collect>>} r
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

module.exports = { collect, report, publicIp, isPrivateIp };
