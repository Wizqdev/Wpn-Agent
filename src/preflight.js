// Preflight — inspect the machine BEFORE doing any work and print what was
// found. The operator should be able to read this and sanity-check the box.

const os = require("os");
const fs = require("fs");
const { tryRun } = require("./util");

const osRelease = () => {
  try {
    const raw = fs.readFileSync("/etc/os-release", "utf8");
    const get = (k) => (raw.match(new RegExp(`^${k}="?([^"\\n]+)"?`, "m")) || [])[1];
    return { id: get("ID") || "linux", pretty: get("PRETTY_NAME") || "Linux" };
  } catch {
    return { id: "linux", pretty: "Linux" };
  }
};

const detectPkgMgr = () => {
  for (const m of ["apt-get", "dnf", "yum", "pacman", "zypper"]) {
    if (tryRun(`command -v ${m}`)) return m;
  }
  return null;
};

const publicIp = () =>
  tryRun("curl -s4 --max-time 5 ifconfig.me") ||
  tryRun("curl -s4 --max-time 5 icanhazip.com") ||
  tryRun("hostname -I | awk '{print $1}'") ||
  null;

const portFree = (port, proto) => {
  const flag = proto === "udp" ? "-lun" : "-ltn";
  const out = tryRun(`ss ${flag} 2>/dev/null | grep -c ':${port} '`);
  return out === "0" || out === null; // null → ss missing, assume free
};

function collect({ agentPort, wgPort }) {
  const osr = osRelease();
  const wgVer = tryRun("wg --version | awk '{print $2}'");
  const fwd4 = tryRun("sysctl -n net.ipv4.ip_forward 2>/dev/null") === "1";
  const fwd6 =
    tryRun("sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null") === "1";

  return {
    os: osr,
    kernel: os.release(),
    arch: os.arch(),
    hostname: os.hostname(),
    node: process.version,
    ipv4: publicIp(),
    wanIf:
      tryRun("ip route show default | awk '/default/ {print $5; exit}'") ||
      "eth0",
    pkgMgr: detectPkgMgr(),
    systemd: !!tryRun("systemctl --version"),
    ufw: !!tryRun("command -v ufw"),
    wg: { installed: !!wgVer, version: wgVer },
    forwarding: { ipv4: fwd4, ipv6: fwd6 },
    ports: {
      agentTcp: { port: agentPort, free: portFree(agentPort, "tcp") },
      wgUdp: { port: wgPort, free: portFree(wgPort, "udp") },
    },
    wgUp: (tryRun("wg show interfaces") || "").split(/\s+/).includes("wg0"),
  };
}

const row = (k, v) =>
  console.log(`   ${k.padEnd(18)} ${typeof v === "boolean" ? (v ? "yes" : "no") : v}`);

function report(r) {
  console.log("\n──────────────── machine ────────────────");
  row("os", `${r.os.pretty} (${r.os.id})`);
  row("kernel/arch", `${r.kernel} / ${r.arch}`);
  row("hostname", r.hostname);
  row("node", r.node);
  row("public ipv4", r.ipv4 || "unknown");
  row("wan iface", r.wanIf);
  row("pkg manager", r.pkgMgr || "none found");
  row("systemd", r.systemd);
  row("ufw", r.ufw);
  console.log("──────────────── wireguard ──────────────");
  row("wg installed", r.wg.installed ? r.wg.version : "no — will install");
  row("wg0 up", r.wgUp);
  row("ip_forward v4", r.forwarding.ipv4);
  row("ip_forward v6", r.forwarding.ipv6);
  console.log("──────────────── ports ───────────────────");
  row(`tcp/${r.ports.agentTcp.port}`, r.ports.agentTcp.free ? "free" : "TAKEN!");
  row(`udp/${r.ports.wgUdp.port}`, r.ports.wgUdp.free ? "free" : "taken");
  console.log("─────────────────────────────────────────\n");
}

module.exports = { collect, report, publicIp };
