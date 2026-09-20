// WireGuard lifecycle — install, wg0 config, peer add/remove, stats.
// Everything here needs root; the agent refuses to run without it.

const fs = require("fs");
const { run, tryRun, log } = require("./util");

const WG_IFACE = "wg0";
const WG_CONF = "/etc/wireguard/wg0.conf";
const WG_KEY_FILE = "/etc/wireguard/server.key";
const SUBNET_GW = "10.66.0.1/24";

const INSTALLERS = {
  "apt-get": "apt-get update -qq && apt-get install -y -qq wireguard iptables",
  dnf: "dnf install -y -q wireguard-tools iptables",
  yum: "yum install -y -q wireguard-tools iptables",
  pacman: "pacman -S --noconfirm --needed wireguard-tools iptables",
  zypper: "zypper -n install wireguard-tools iptables",
};

function ensureInstalled(r) {
  if (r.wg.installed) return log.ok(`wireguard already installed (${r.wg.version})`);
  const installer = INSTALLERS[r.pkgMgr];
  if (!installer) throw new Error("no supported package manager — install wireguard manually");
  log.info(`installing wireguard via ${r.pkgMgr}…`);
  run(installer, { timeout: 300000 });
  log.ok("wireguard installed");
}

function ensureConfig(r, wgPort) {
  fs.mkdirSync("/etc/wireguard", { mode: 0o700, recursive: true });

  if (!fs.existsSync(WG_KEY_FILE)) {
    fs.writeFileSync(WG_KEY_FILE, run("wg genkey") + "\n", { mode: 0o600 });
    log.ok("server keypair generated");
  }

  if (!fs.existsSync(WG_CONF)) {
    const priv = fs.readFileSync(WG_KEY_FILE, "utf8").trim();
    fs.writeFileSync(
      WG_CONF,
      [
        "[Interface]",
        `Address = ${SUBNET_GW}`,
        `ListenPort = ${wgPort}`,
        `PrivateKey = ${priv}`,
        `PostUp = iptables -A FORWARD -i ${WG_IFACE} -j ACCEPT; iptables -A FORWARD -o ${WG_IFACE} -j ACCEPT; iptables -t nat -A POSTROUTING -o ${r.wanIf} -j MASQUERADE`,
        `PostDown = iptables -D FORWARD -i ${WG_IFACE} -j ACCEPT; iptables -D FORWARD -o ${WG_IFACE} -j ACCEPT; iptables -t nat -D POSTROUTING -o ${r.wanIf} -j MASQUERADE`,
        "",
      ].join("\n"),
      { mode: 0o600 }
    );
    log.ok(`wg0.conf written (nat on ${r.wanIf})`);
  }
}

function ensureForwarding(r) {
  fs.writeFileSync(
    "/etc/sysctl.d/99-wpn.conf",
    "net.ipv4.ip_forward=1\nnet.ipv6.conf.all.forwarding=1\n"
  );
  tryRun("sysctl --system -q");
  log.ok("ip forwarding enabled");
}

function ensureUp(r, wgPort) {
  if (r.wgUp) return log.ok("wg0 already up");
  if (r.systemd) {
    if (tryRun(`systemctl enable --now wg-quick@${WG_IFACE}`) !== null) {
      return log.ok("wg0 up via systemd (wg-quick@wg0)");
    }
    log.warn("systemd start failed — falling back to wg-quick");
  }
  run(`wg-quick up ${WG_CONF}`);
  log.ok("wg0 up via wg-quick");
}

function ensureFirewall(r, wgPort, agentPort) {
  if (!r.ufw) return;
  tryRun(`ufw allow ${wgPort}/udp`);
  tryRun(`ufw allow ${agentPort}/tcp`);
  log.ok(`ufw: opened udp/${wgPort} + tcp/${agentPort}`);
}

// If wg0 was already up before we existed (pre-configured box), its conf may
// lack our NAT/forward rules — add them live AND persist into wg0.conf so a
// reboot doesn't silently break the tunnel.
function ensureNat(r) {
  const fwd = `FORWARD -i ${WG_IFACE} -j ACCEPT`;
  const fwdOut = `FORWARD -o ${WG_IFACE} -j ACCEPT`;
  const nat = `POSTROUTING -o ${r.wanIf} -j MASQUERADE`;

  const missing = [];
  for (const rule of [
    `iptables -C ${fwd}`,
    `iptables -C ${fwdOut}`,
    `iptables -t nat -C ${nat}`,
  ]) {
    if (tryRun(rule) === null) missing.push(rule.replace(" -C ", " -A "));
  }
  for (const add of missing) tryRun(add);
  if (missing.length) log.ok(`nat/forward rules added (${missing.length})`);

  // persist — only if the conf doesn't already MASQUERADE on PostUp
  if (fs.existsSync(WG_CONF) && !fs.readFileSync(WG_CONF, "utf8").includes("MASQUERADE")) {
    let conf = fs.readFileSync(WG_CONF, "utf8");
    const up = `iptables -A ${fwd}; iptables -A ${fwdOut}; iptables -t nat -A ${nat}`;
    const down = `iptables -D ${fwd}; iptables -D ${fwdOut}; iptables -t nat -D ${nat}`;
    if (/^PostUp\s*=/m.test(conf)) {
      conf = conf.replace(/^(PostUp\s*=.*)$/m, `$1; ${up}`);
      conf = /^PostDown\s*=/m.test(conf)
        ? conf.replace(/^(PostDown\s*=.*)$/m, `$1; ${down}`)
        : conf.replace(/^(PostUp\s*=.*)$/m, `$1\nPostDown = ${down}`);
    } else {
      conf = conf.replace(/^(PrivateKey\s*=.*)$/m, `$1\nPostUp = ${up}\nPostDown = ${down}`);
    }
    fs.writeFileSync(WG_CONF, conf, { mode: 0o600 });
    log.ok("nat rules persisted into wg0.conf");
  }
}

function ensure(r, { wgPort, agentPort }) {
  ensureInstalled(r);
  ensureConfig(r, wgPort);
  ensureForwarding(r);
  ensureUp(r, wgPort);
  ensureNat(r);
  ensureFirewall(r, wgPort, agentPort);
}

// --- peers ------------------------------------------------------------------
// Peers live in the runtime (wg set) AND in wg0.conf (marker-commented blocks)
// so they survive reboots.

const WG_KEY_RE = /^[A-Za-z0-9+/]{43}=$/;
const IPV4_RE = /^\d{1,3}(\.\d{1,3}){3}$/;

function addPeer(publicKey, address) {
  if (!WG_KEY_RE.test(publicKey)) throw new Error("publicKey must be a base64 WireGuard key");
  if (!IPV4_RE.test(address)) throw new Error("address must be an IPv4 tunnel address");

  run(`wg set ${WG_IFACE} peer '${publicKey}' allowed-ips ${address}/32 persistent-keepalive 25`);

  let conf = fs.readFileSync(WG_CONF, "utf8");
  if (!conf.includes(publicKey)) {
    conf += [
      `# wpn-peer ${address}`,
      "[Peer]",
      `PublicKey = ${publicKey}`,
      `AllowedIPs = ${address}/32`,
      "PersistentKeepalive = 25",
      "",
    ].join("\n");
    fs.writeFileSync(WG_CONF, conf, { mode: 0o600 });
  }
  return { added: true, address };
}

function removePeer(publicKey) {
  if (!WG_KEY_RE.test(publicKey)) throw new Error("invalid peer key");
  tryRun(`wg set ${WG_IFACE} peer '${publicKey}' remove`);

  const lines = fs.readFileSync(WG_CONF, "utf8").split("\n");
  const out = [];
  let skipping = false;
  for (const line of lines) {
    if (line.includes(publicKey)) {
      // drop the marker comment + [Peer] header already pushed for this block
      while (out.length) {
        const top = out[out.length - 1];
        if (top.startsWith("# wpn-peer") || top.trim() === "[Peer]") out.pop();
        else break;
      }
      skipping = true;
      continue;
    }
    if (skipping) {
      if (line.trim() === "" || line.trim() === "[Peer]" || line.startsWith("#")) {
        skipping = false;
      } else {
        continue; // AllowedIPs / PersistentKeepalive of the removed peer
      }
    }
    out.push(line);
  }
  fs.writeFileSync(WG_CONF, out.join("\n"), { mode: 0o600 });
  return { removed: true };
}

// `wg show wg0 dump` — peer lines have 9 tab-separated fields:
// iface, pubkey, psk, endpoint, allowed-ips, handshake-epoch, rx, tx, keepalive
function dump() {
  const out = tryRun(`wg show ${WG_IFACE} dump`);
  if (!out) return { peers: [] };
  const peers = [];
  for (const line of out.split("\n")) {
    const f = line.split("\t");
    if (f.length !== 9) continue;
    peers.push({
      publicKey: f[1],
      endpoint: f[3] === "(none)" ? null : f[3],
      allowedIps: f[4],
      latestHandshake: parseInt(f[5], 10) || 0,
      rx: parseInt(f[6], 10) || 0,
      tx: parseInt(f[7], 10) || 0,
    });
  }
  return { peers };
}

function stats() {
  const { peers } = dump();
  const now = Math.floor(Date.now() / 1000);
  return {
    peerCount: peers.length,
    activePeers: peers.filter(
      (p) => p.latestHandshake && now - p.latestHandshake < 180
    ).length,
    rxBytes: peers.reduce((a, p) => a + p.rx, 0),
    txBytes: peers.reduce((a, p) => a + p.tx, 0),
    load: Math.min(100, Math.round((os_load() / os_cpus()) * 100)),
    peers,
  };
}

const os_load = () => require("os").loadavg()[0];
const os_cpus = () => require("os").cpus().length;

// Live interface facts — the source of truth when wg0 predates the agent.
function liveInfo() {
  const listenPort = parseInt(tryRun(`wg show ${WG_IFACE} listen-port`), 10) || null;
  const addrRaw = tryRun(`ip -o -4 addr show dev ${WG_IFACE} | awk '{print $4; exit}'`);
  let subnet = null;
  if (addrRaw) {
    const [ip, mask] = addrRaw.split("/");
    subnet = mask === "24" ? `${ip.split(".").slice(0, 3).join(".")}.0/24` : addrRaw;
  }
  return { listenPort, subnet, address: addrRaw };
}

// Prefer the live interface's pubkey — a pre-existing wg0 may use a different key.
function serverPubKey(pubFile) {
  return (
    tryRun(`wg show ${WG_IFACE} public-key`) ||
    (pubFile && fs.existsSync(pubFile)
      ? fs.readFileSync(pubFile, "utf8").trim()
      : tryRun(`wg pubkey < ${WG_KEY_FILE}`))
  );
}

module.exports = { ensure, addPeer, removePeer, dump, stats, serverPubKey, liveInfo, WG_IFACE, LISTEN_GW: SUBNET_GW };
