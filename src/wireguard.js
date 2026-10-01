
"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const { run, runBin, tryRun, tryRunBin, log, err: httpErr } = require("./util");
const { confLock } = require("./lock");
const firewall = require("./firewall");

const WG_IFACE    = process.env.WPN_WG_IFACE || "wg0";
const WG_CONF     = process.env.WPN_WG_CONF || `/etc/wireguard/${WG_IFACE}.conf`;
const WG_KEY_FILE = "/etc/wireguard/server.key";
const SUBNET_V4   = process.env.WPN_SUBNET_V4 || "10.66.0.1/24";
const SUBNET_V6   = process.env.WPN_SUBNET_V6 || "fd00:66::1/64";

const INSTALLERS = {
  "apt-get": "apt-get update -qq && apt-get install -y -qq wireguard iptables",
  dnf:       "dnf install -y -q wireguard-tools iptables",
  yum:       "yum install -y -q wireguard-tools iptables",
  pacman:    "pacman -S --noconfirm --needed wireguard-tools iptables",
  zypper:    "zypper -n install wireguard-tools iptables",
};

const WG_SET_TIMEOUT_MS = 10_000;

function writeFileAtomic(file, data, mode = 0o600) {
  const tmp = `${file}.tmp`;
  const fd  = fs.openSync(tmp, "w", mode);
  try {
    fs.fchmodSync(fd, mode);
    fs.writeFileSync(fd, data);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.renameSync(tmp, file);
  try {
    const dfd = fs.openSync(path.dirname(file), "r");
    try { fs.fsyncSync(dfd); } finally { fs.closeSync(dfd); }
  } catch {}
}

const WG_KEY_RE = /^[A-Za-z0-9+/]{43}=$/;
const IPV4_RE   = /^\d{1,3}(\.\d{1,3}){3}$/;

const ipToInt = (ip) =>
  ip.split(".").reduce((acc, o) => ((acc << 8) | (parseInt(o, 10) & 0xff)) >>> 0, 0);

const isValidIPv4 = (ip) =>
  IPV4_RE.test(ip) && ip.split(".").every((o) => parseInt(o, 10) <= 255);

function expandIPv6(ip) {
  if (typeof ip !== "string" || ip === "" || !/^[0-9a-fA-F:]+$/.test(ip)) {
    return null;
  }
  const side = (s) => {
    if (s === "") return [];
    const parts = s.split(":");
    return parts.every((p) => /^[0-9a-fA-F]{1,4}$/.test(p)) ? parts : null;
  };
  const halves = ip.split("::");
  if (halves.length > 2) return null;
  const head = side(halves[0]);
  if (!head) return null;
  if (halves.length === 1) {
    return head.length === 8
      ? head.map((x) => x.padStart(4, "0").toLowerCase())
      : null;
  }
  const tail = side(halves[1]);
  if (!tail) return null;
  const missing = 8 - head.length - tail.length;
  if (missing < 1) return null;
  return [...head, ...Array(missing).fill("0"), ...tail].map((x) =>
    x.padStart(4, "0").toLowerCase()
  );
}

function addrInSubnet(ip, cidr) {
  const [base, bitsRaw] = cidr.split("/");
  const bits = parseInt(bitsRaw, 10);
  if (ip.includes(":")) {
    const addr = expandIPv6(ip);
    const net  = expandIPv6(base);
    if (!addr || !net || !Number.isInteger(bits) || bits < 0 || bits > 128) return false;
    const groups = Math.floor(bits / 16);
    for (let i = 0; i < groups; i++) if (addr[i] !== net[i]) return false;
    const rem = bits % 16;
    if (!rem) return true;
    const mask = (0xffff << (16 - rem)) & 0xffff;
    return (parseInt(addr[groups], 16) & mask) === (parseInt(net[groups], 16) & mask);
  }
  if (!isValidIPv4(ip) || !isValidIPv4(base)) return false;
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return (ipToInt(ip) & mask) === (ipToInt(base) & mask);
}

const normAddr = (a) => {
  a = a.trim().toLowerCase();
  if (!a.includes(":")) return a;
  const ex = expandIPv6(a);
  return ex ? ex.join(":") : a;
};

async function ensureInstalled(r) {
  if (r.wg.installed) {
    return log.ok(`wireguard already installed (${r.wg.version})`);
  }
  const installer = INSTALLERS[r.pkgMgr];
  if (!installer) {
    throw new Error("no supported package manager — install wireguard manually");
  }
  log.info(`installing wireguard via ${r.pkgMgr}…`);
  await run(installer, { timeout: 300_000 });
  log.ok("wireguard installed");
}

function genKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("x25519", {
    publicKeyEncoding:  { format: "jwk" },
    privateKeyEncoding: { format: "jwk" },
  });
  const b64 = (u) => Buffer.from(u, "base64url").toString("base64");
  return { priv: b64(privateKey.d), pub: b64(publicKey.x) };
}

const X25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b656e04220420", "hex");

function derivePubKey(privB64) {
  const raw = Buffer.from(privB64.trim(), "base64");
  if (raw.length !== 32) throw new Error("invalid WireGuard private key length");
  const privKey = crypto.createPrivateKey({
    key: Buffer.concat([X25519_PKCS8_PREFIX, raw]),
    format: "der",
    type: "pkcs8",
  });
  const pubDer = crypto.createPublicKey(privKey).export({ format: "der", type: "spki" });

  return pubDer.subarray(-32).toString("base64");
}

async function ensureServerKey() {
  fs.mkdirSync("/etc/wireguard", { mode: 0o700, recursive: true });
  if (!fs.existsSync(WG_KEY_FILE)) {
    const priv =
      (await tryRunBin("wg", ["genkey"])) || genKeyPair().priv;
    fs.writeFileSync(WG_KEY_FILE, priv + "\n", { mode: 0o600 });
    log.ok("server keypair generated");
  }
  const priv = fs.readFileSync(WG_KEY_FILE, "utf8").trim();
  const pub =
    (await tryRun(`wg pubkey < ${WG_KEY_FILE}`)) || derivePubKey(priv);
  return { priv, pub };
}

async function ensureConfig(r, wgPort) {
  await ensureServerKey();

  if (!fs.existsSync(WG_CONF)) {
    const priv = fs.readFileSync(WG_KEY_FILE, "utf8").trim();
    const { up, down } = await firewall.confNatRules(r.wanIf, WG_IFACE);
    writeFileAtomic(
      WG_CONF,
      [
        "[Interface]",
        `Address = ${SUBNET_V4}, ${SUBNET_V6}`,
        `ListenPort = ${wgPort}`,
        `PrivateKey = ${priv}`,
        `PostUp = ${up}`,
        `PostDown = ${down}`,
        "",
      ].join("\n"),
      0o600
    );
    log.ok(`${WG_IFACE}.conf written (nat on ${r.wanIf}, backend: ${await firewall.backend()})`);
  }
}

async function ensureForwarding() {
  fs.writeFileSync(
    "/etc/sysctl.d/99-wpn.conf",
    "net.ipv4.ip_forward=1\nnet.ipv6.conf.all.forwarding=1\n"
  );
  await tryRunBin("sysctl", ["--system", "-q"]);
  log.ok("ip forwarding enabled");
}

async function ensureUp(r) {
  if (r.wgUp) return log.ok(`${WG_IFACE} already up`);
  if (r.systemd) {
    if ((await tryRunBin("systemctl", ["enable", "--now", `wg-quick@${WG_IFACE}`])) !== null) {
      return log.ok(`${WG_IFACE} up via systemd (wg-quick@${WG_IFACE})`);
    }
    log.warn("systemd start failed — falling back to wg-quick");
  }
  await runBin("wg-quick", ["up", WG_CONF]);
  log.ok(`${WG_IFACE} up via wg-quick`);
}

async function ensureNat(r) {
  const added = await firewall.ensureLiveNat(r.wanIf, WG_IFACE);
  if (added) log.ok(`nat/forward/clamp rules applied (backend: ${await firewall.backend()})`);

  if (fs.existsSync(WG_CONF)) {
    const release = await confLock.acquire();
    try {
      const before = fs.readFileSync(WG_CONF, "utf8");
      const after  = await firewall.patchConfNat(before, r.wanIf, WG_IFACE);
      if (after !== before) {
        writeFileAtomic(WG_CONF, after);
        log.ok("nat rules persisted into wg0.conf");
      }
    } finally {
      release();
    }
  }
}

async function ensure(r, { wgPort, agentPort, echoPort }) {
  await ensureInstalled(r);
  await ensureConfig(r, wgPort);
  await ensureForwarding();
  await ensureUp(r);
  await ensureNat(r);
  await firewall.openPorts(r.ufw, wgPort, agentPort, echoPort);
}

function parseConfPeers(conf) {
  const peers = [];
  const blocks = conf.split(/^\s*\[/m).slice(1);
  for (const block of blocks) {
    if (!block.startsWith("Peer]")) continue;
    const pub = (block.match(/^\s*PublicKey\s*=\s*(\S+)/m) || [])[1];
    const allowed = (block.match(/^\s*AllowedIPs\s*=\s*(.+)$/m) || [])[1] || "";
    if (pub) {
      peers.push({
        publicKey:  pub.trim(),
        allowedIps: allowed.split(",").map((s) => s.trim().split("/")[0]).filter(Boolean),
      });
    }
  }
  return peers;
}


function removePeerFromConf(conf, publicKey) {
  const lines   = conf.split("\n");
  const out     = [];
  let skipping  = false;

  for (const line of lines) {
    const t = line.trim();
    if (skipping) {
      if (t === "" ) continue;
      if (t.startsWith("[") || t.startsWith("#")) skipping = false;
      else continue;
    }
    if (t === "[Peer]") {
      out.push(line);
      continue;
    }
    if (line.includes(publicKey)) {
      while (out.length) {
        const top = out[out.length - 1];
        if (top.trim() === "[Peer]" || top.trim().startsWith("# wpn-peer")) out.pop();
        else break;
      }
      skipping = true;
      continue;
    }
    out.push(line);
  }
  return out.join("\n");
}

function upsertPeerConf(conf, { publicKey, address, allowedIps }) {
  const base = conf.includes(publicKey)
    ? removePeerFromConf(conf, publicKey).replace(/\n{3,}/g, "\n\n")
    : conf;
  return (
    base +
    `# wpn-peer ${address}\n` +
    `[Peer]\n` +
    `PublicKey = ${publicKey}\n` +
    `AllowedIPs = ${allowedIps}\n` +
    `PersistentKeepalive = 25\n` +
    `\n`
  );
}

function confAddresses() {
  try {
    const m = fs.readFileSync(WG_CONF, "utf8").match(/^\s*Address\s*=\s*(.+)$/m);
    return m ? m[1].split(",").map((s) => s.trim()).filter(Boolean) : [];
  } catch {
    return [];
  }
}

async function tunnelNets() {
  const cfg = confAddresses();
  const [live4, live6] = await Promise.all([
    tryRun(`ip -o -4 addr show dev ${WG_IFACE} | awk '{print $4; exit}'`),
    tryRun(`ip -o -6 addr show dev ${WG_IFACE} scope global | awk '{print $4; exit}'`),
  ]);
  return {
    v4: live4 || cfg.find((a) => !a.includes(":")) || SUBNET_V4,
    v6: live6 || cfg.find((a) => a.includes(":")) || SUBNET_V6,
  };
}

async function validatePeerAddrs(addrs) {
  const nets     = await tunnelNets();
  const serverV4 = nets.v4.split("/")[0];
  const serverV6 = normAddr(nets.v6.split("/")[0]);

  for (const a of addrs) {
    const isV6 = a.includes(":");
    if (isV6 ? !expandIPv6(a) : !isValidIPv4(a)) {
      throw httpErr(400, `address ${a} is not a valid IPv4 or IPv6 address`);
    }
    if (!addrInSubnet(a, isV6 ? nets.v6 : nets.v4)) {
      throw httpErr(
        400,
        `address ${a} is outside the node subnet ` +
          `(${isV6 ? nets.v6 : nets.v4})`
      );
    }
    if (normAddr(a) === (isV6 ? serverV6 : serverV4)) {
      throw httpErr(400, `address ${a} collides with the server's own tunnel address`);
    }
  }
}

async function claimedAddrs(excludeKey) {
  const claimed = new Map();
  const claim = (pub, ip) => {
    if (pub !== excludeKey) claimed.set(normAddr(ip), pub);
  };
  for (const p of (await dump()).peers) {
    for (const ip of p.allowedIps.split(",")) claim(p.publicKey, ip.trim().split("/")[0]);
  }
  if (fs.existsSync(WG_CONF)) {
    for (const p of parseConfPeers(fs.readFileSync(WG_CONF, "utf8"))) {
      for (const ip of p.allowedIps) claim(p.publicKey, ip);
    }
  }
  return claimed;
}

async function rollbackLive(publicKey, prev) {
  try {
    if (prev) {
      await runBin("wg", [
        "set", WG_IFACE, "peer", publicKey,
        "allowed-ips", prev.allowedIps === "(none)" ? "" : prev.allowedIps,
        "persistent-keepalive", "25",
      ], { timeout: WG_SET_TIMEOUT_MS });
    } else {
      await runBin("wg", ["set", WG_IFACE, "peer", publicKey, "remove"], {
        timeout: WG_SET_TIMEOUT_MS,
      });
    }
    return null;
  } catch (e) {
    return e;
  }
}

async function persistFailure(what, publicKey, prev, cause) {
  const short = publicKey.slice(0, 8);
  const rbErr = await rollbackLive(publicKey, prev);
  if (rbErr) {
    log.err(
      `peer ${what} ${short}: persist failed (${cause.message}) AND rollback failed ` +
        `(${rbErr.message}) — live state and ${WG_CONF} have DRIFTED`
    );
    return httpErr(
      500,
      `failed to persist peer ${what} and rollback failed — live/conf drift on ${short}…`
    );
  }
  log.warn(`peer ${what} ${short}: persist failed (${cause.message}) — live change rolled back`);
  return httpErr(500, `failed to persist peer ${what} (${cause.message}); change rolled back`);
}

async function addPeer(publicKey, address) {
  if (typeof publicKey !== "string" || !WG_KEY_RE.test(publicKey)) {
    throw httpErr(400, "publicKey must be a base64 WireGuard key");
  }
  if (typeof address !== "string" || !address.trim()) {
    throw httpErr(400, "address is required");
  }

  const addrs = address.split(",").map((a) => a.trim()).filter(Boolean);
  await validatePeerAddrs(addrs);

  const allowedIps = addrs
    .map((a) => (a.includes(":") ? `${a}/128` : `${a}/32`))
    .join(",");

  const release = await confLock.acquire();
  try {

    const claimed = await claimedAddrs(publicKey);
    for (const a of addrs) {
      const owner = claimed.get(normAddr(a));
      if (owner) {
        throw httpErr(
          409,
          `address ${a} is already assigned to peer ${owner.slice(0, 8)}…`
        );
      }
    }

    const prev = (await dump()).peers.find((p) => p.publicKey === publicKey);

    await runBin("wg", [
      "set", WG_IFACE,
      "peer", publicKey,
      "allowed-ips", allowedIps,
      "persistent-keepalive", "25",
    ], { timeout: WG_SET_TIMEOUT_MS });

    if (!fs.existsSync(WG_CONF)) {
      log.warn(`${WG_CONF} missing — peer added live but not persisted`);
      return { added: true, address, persisted: false };
    }
    try {
      const conf = fs.readFileSync(WG_CONF, "utf8");
      writeFileAtomic(WG_CONF, upsertPeerConf(conf, { publicKey, address, allowedIps }));
    } catch (e) {
      throw await persistFailure("add", publicKey, prev, e);
    }

    return { added: true, address };
  } finally {
    release();
  }
}

async function removePeer(publicKey) {
  if (typeof publicKey !== "string" || !WG_KEY_RE.test(publicKey)) {
    throw httpErr(400, "invalid peer key");
  }

  const release = await confLock.acquire();
  try {
    const prev = (await dump()).peers.find((p) => p.publicKey === publicKey);
    await tryRunBin("wg", ["set", WG_IFACE, "peer", publicKey, "remove"], {
      timeout: WG_SET_TIMEOUT_MS,
    });

    if (!fs.existsSync(WG_CONF)) {
      return { removed: true, persisted: false };
    }
    try {
      const before = fs.readFileSync(WG_CONF, "utf8");
      const after  = removePeerFromConf(before, publicKey);
      if (after !== before) writeFileAtomic(WG_CONF, after);
    } catch (e) {

      throw prev
        ? await persistFailure("remove", publicKey, prev, e)
        : httpErr(500, `failed to persist peer removal (${e.message})`);
    }
    return { removed: true };
  } finally {
    release();
  }
}

function parseDump(out, iface) {
  const peers = [];
  for (const line of out.split("\n")) {
    const f = line.split("\t");
    let base;
    if (f.length === 9 && f[0] === iface) base = 1;
    else if (f.length === 8)             base = 0;
    else continue;
    peers.push({
      publicKey:       f[base],
      endpoint:        f[base + 2] === "(none)" ? null : f[base + 2],
      allowedIps:      f[base + 3] || "",
      latestHandshake: Math.max(0, parseInt(f[base + 4], 10) || 0),
      rx:              Math.max(0, parseInt(f[base + 5], 10) || 0),
      tx:              Math.max(0, parseInt(f[base + 6], 10) || 0),
    });
  }
  return peers;
}


async function dump() {
  const out = await tryRunBin("wg", ["show", WG_IFACE, "dump"]);
  return { peers: out ? parseDump(out, WG_IFACE) : [] };
}

async function knownPeers() {
  const byKey = new Map();
  for (const p of (await dump()).peers) {
    byKey.set(p.publicKey, { ...p, confOnly: false });
  }
  const mergeIps = (entry, ips) => {
    const set = new Set(
      String(entry.allowedIps || "")
        .split(",")
        .map((s) => s.trim().split("/")[0])
        .filter(Boolean)
    );
    for (const ip of ips) {
      const a = String(ip).trim().split("/")[0];
      if (a) set.add(a);
    }
    entry.allowedIps = [...set]
      .map((a) => (a.includes(":") ? `${a}/128` : `${a}/32`))
      .join(",");
  };
  if (fs.existsSync(WG_CONF)) {
    for (const cp of parseConfPeers(fs.readFileSync(WG_CONF, "utf8"))) {
      const entry =
        byKey.get(cp.publicKey) || {
          publicKey:       cp.publicKey,
          endpoint:        null,
          allowedIps:      "",
          latestHandshake: 0,
          rx:              0,
          tx:              0,
          confOnly:        true,
        };
      mergeIps(entry, cp.allowedIps);
      byKey.set(cp.publicKey, entry);
    }
  }
  return [...byKey.values()];
}

async function stats() {
  const { peers } = await dump();
  const now       = Math.floor(Date.now() / 1_000);
  let rxBytes = 0, txBytes = 0, activePeers = 0;

  for (const p of peers) {
    rxBytes += p.rx;
    txBytes += p.tx;
    if (p.latestHandshake && now - p.latestHandshake < 180) activePeers++;
  }

  return {
    peerCount: peers.length,
    activePeers,
    rxBytes,
    txBytes,
    load: Math.min(100, Math.round((os.loadavg()[0] / os.cpus().length) * 100)),
    peers,
  };
}

let _version;

function version() {
  if (_version !== undefined) return _version;
  _version = (async () => {
    const out = await tryRunBin("wg", ["--version"]);
    return (out && (out.match(/v[\d.]+/) || [])[0]) || out || null;
  })();
  return _version;
}

async function liveInfo() {
  const listenPort = parseInt(
    (await tryRunBin("wg", ["show", WG_IFACE, "listen-port"])) || "",
    10
  ) || null;
  const addrRaw = await tryRun(
    `ip -o -4 addr show dev ${WG_IFACE} | awk '{print $4; exit}'`
  );
  let subnet = null;
  if (addrRaw) {
    const [ip, mask] = addrRaw.split("/");
    subnet = mask === "24" ? `${ip.split(".").slice(0, 3).join(".")}.0/24` : addrRaw;
  }
  return { listenPort, subnet, address: addrRaw };
}

async function serverPubKey(pubFile) {
  return (
    (await tryRunBin("wg", ["show", WG_IFACE, "public-key"])) ||
    (pubFile && fs.existsSync(pubFile)
      ? fs.readFileSync(pubFile, "utf8").trim()
      : await tryRun(`wg pubkey < ${WG_KEY_FILE}`))
  );
}

module.exports = {
  ensure,
  ensureServerKey,
  addPeer,
  removePeer,
  dump,
  knownPeers,
  stats,
  serverPubKey,
  liveInfo,
  version,
  WG_IFACE,
  SUBNET_V4,
  SUBNET_V6,
  WG_CONF,

  _WG_KEY_RE:        WG_KEY_RE,
  _IPV4_RE:          IPV4_RE,
  _isValidIPv4:      isValidIPv4,
  _expandIPv6:       expandIPv6,
  _addrInSubnet:     addrInSubnet,
  _normAddr:         normAddr,
  _parseDump:        parseDump,
  _genKeyPair:       genKeyPair,
  _derivePubKey:     derivePubKey,
  _parseConfPeers:   parseConfPeers,
  _removePeerFromConf: removePeerFromConf,
  _upsertPeerConf:   upsertPeerConf,
};
