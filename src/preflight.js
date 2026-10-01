
"use strict";

const os = require("os");
const fs = require("fs");
const https = require("https");
const { tryRun, tryRunBin } = require("./util");

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

const detectPkgMgr = async () => {
  for (const m of ["apt-get", "dnf", "yum", "pacman", "zypper"]) {
    if (await tryRun(`command -v ${m}`)) return m;
  }
  return null;
};

const PUBLIC_IP_TTL_MS = 10 * 60_000;

let _publicIpCache;

const isPrivateIp = (ip) => {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
    return false;
  }
  const [a, b] = parts;
  if (a === 0) return true;
  if (a === 10) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  if (a === 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 0) return true;
  if (a === 192 && b === 168) return true;
  if (a === 198 && (b === 18 || b === 19)) return true;
  if (a >= 224) return true;
  return false;
};

const looksLikeIPv4 = (ip) =>
  /^\d{1,3}(\.\d{1,3}){3}$/.test(ip) &&
  ip.split(".").every((o) => parseInt(o, 10) <= 255);

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
          if (data.length > 64) req.destroy();
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

      return looksLikeIPv4(localIp || "") ? localIp : null;
    })(),
  };

  return _publicIpCache.p;
};


const portFree = async (port, proto) => {
  const flag = proto === "udp" ? "-lun" : "-ltn";
  const out = await tryRun(`ss ${flag} 2>/dev/null | grep -c ':${port} '`);
  return out === "0" || out === null;
};

async function collect({ agentPort, wgPort }) {
  const osr   = osRelease();
  const wgVer = ((await tryRunBin("wg", ["--version"])) || "").split(/\s+/)[1] || null;
  const fwd4  = (await tryRunBin("sysctl", ["-n", "net.ipv4.ip_forward"])) === "1";
  const fwd6  = (await tryRunBin("sysctl", ["-n", "net.ipv6.conf.all.forwarding"])) === "1";

  const [ipv4, wanIf, pkgMgr, systemd, ufw, agentFree, wgFree, ifaces] =
    await Promise.all([
      publicIp(),
      tryRun("ip route show default | awk '/default/ {print $5; exit}'"),
      detectPkgMgr(),
      tryRunBin("systemctl", ["--version"]),
      tryRun("command -v ufw"),
      portFree(agentPort, "tcp"),
      portFree(wgPort, "udp"),
      tryRunBin("wg", ["show", "interfaces"]),
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

const row = (k, v) =>
  process.stdout.write(
    `   ${k.padEnd(18)} ${typeof v === "boolean" ? (v ? "yes" : "no") : v}\n`
  );

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
