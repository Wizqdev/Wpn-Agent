/**
 * @fileoverview WireGuard lifecycle — install, `wg0` config, peer management,
 * stats, and interface introspection.
 *
 * All conf-file mutations go through the {@link confLock} async mutex so
 * concurrent API requests cannot corrupt `wg0.conf`.  All `wg` and `ip`
 * binary calls use {@link runBin} (arg arrays, no shell) to eliminate any
 * injection surface — and are async so they never block the event loop.
 *
 * NAT/forwarding/clamp rules are delegated to {@link module:firewall} which
 * handles both iptables and nftables backends transparently.
 */

"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const { run, runBin, tryRun, tryRunBin, log, err: httpErr } = require("./util");
const { confLock } = require("./lock");
const firewall = require("./firewall");

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const WG_IFACE    = process.env.WPN_WG_IFACE || "wg0";
/** `WPN_WG_CONF` is a test hook; production always uses /etc/wireguard. */
const WG_CONF     = process.env.WPN_WG_CONF || `/etc/wireguard/${WG_IFACE}.conf`;
const WG_KEY_FILE = "/etc/wireguard/server.key";
const SUBNET_V4   = process.env.WPN_SUBNET_V4 || "10.66.0.1/24";
const SUBNET_V6   = process.env.WPN_SUBNET_V6 || "fd00:66::1/64";

/** @type {Record<string, string>} Package-manager → install command. */
const INSTALLERS = {
  "apt-get": "apt-get update -qq && apt-get install -y -qq wireguard iptables",
  dnf:       "dnf install -y -q wireguard-tools iptables",
  yum:       "yum install -y -q wireguard-tools iptables",
  pacman:    "pacman -S --noconfirm --needed wireguard-tools iptables",
  zypper:    "zypper -n install wireguard-tools iptables",
};

/** `wg set` calls made while holding {@link confLock} must not hang the API. */
const WG_SET_TIMEOUT_MS = 10_000;

/**
 * Atomically replace `file`: write a sibling temp file (fsync'd), rename it
 * over the original, then fsync the directory.  A crash at any point leaves
 * either the old or the new conf intact — never a truncated one.
 *
 * @param {string} file
 * @param {string} data
 * @param {number} [mode]
 */
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

// ---------------------------------------------------------------------------
// Address validation
// ---------------------------------------------------------------------------

const WG_KEY_RE = /^[A-Za-z0-9+/]{43}=$/;
const IPV4_RE   = /^\d{1,3}(\.\d{1,3}){3}$/;

/** IPv4 dotted-quad → 32-bit int. */
const ipToInt = (ip) =>
  ip.split(".").reduce((acc, o) => ((acc << 8) | (parseInt(o, 10) & 0xff)) >>> 0, 0);

/**
 * Strict IPv4 validation — every octet must be 0–255.
 * @param {string} ip
 * @returns {boolean}
 */
const isValidIPv4 = (ip) =>
  IPV4_RE.test(ip) && ip.split(".").every((o) => parseInt(o, 10) <= 255);

/**
 * Expand an IPv6 address to 8 lowercase hextets, or null if malformed.
 * Handles `::` compression (which must compress at least one group).
 * IPv4-mapped forms (`::ffff:1.2.3.4`) are rejected — tunnel addressing
 * uses native hextets only.
 * @param {string} ip
 * @returns {string[]|null}
 */
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
  if (halves.length > 2) return null; // "::" may appear at most once
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
  if (missing < 1) return null; // "::" must compress at least one group
  return [...head, ...Array(missing).fill("0"), ...tail].map((x) =>
    x.padStart(4, "0").toLowerCase()
  );
}

/**
 * Is `ip` inside `cidr`?  Works for v4 (bitmask) and v6 (hextet prefix compare).
 * @param {string} ip
 * @param {string} cidr - e.g. "10.66.0.1/24" or "fd00:66::1/64".
 * @returns {boolean}
 */
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

/**
 * Normalise an address for comparison (lowercase; v6 expanded+compressed form
 * collapse).  Good enough for equality checks against conf/dump entries.
 * @param {string} a
 * @returns {string}
 */
const normAddr = (a) => {
  a = a.trim().toLowerCase();
  if (!a.includes(":")) return a;
  const ex = expandIPv6(a);
  return ex ? ex.join(":") : a;
};

// ---------------------------------------------------------------------------
// WireGuard setup steps
// ---------------------------------------------------------------------------

/**
 * Install WireGuard via the host's package manager if not already present.
 *
 * @param {object} r - Preflight report.
 */
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

/**
 * Generate a WireGuard keypair in pure Node crypto.  WireGuard keys are
 * X25519 — a 32-byte private scalar and its public point — so the JWK
 * encoding maps 1:1 onto wg's base64 format without needing the `wg` binary
 * (which may not be installed yet on a first-run `--print`).
 *
 * @returns {{ priv: string, pub: string }} base64-encoded keypair.
 */
function genKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("x25519", {
    publicKeyEncoding:  { format: "jwk" },
    privateKeyEncoding: { format: "jwk" },
  });
  const b64 = (u) => Buffer.from(u, "base64url").toString("base64");
  return { priv: b64(privateKey.d), pub: b64(publicKey.x) };
}

/**
 * PKCS8 DER prefix for an X25519 private key —
 * `SEQUENCE { 0, OID 1.3.101.110, OCTET STRING { OCTET STRING { 32 B } } }`.
 * Prepending it lets Node import a raw 32-byte WireGuard scalar directly.
 */
const X25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b656e04220420", "hex");

/**
 * Derive the WireGuard public key for a base64 private scalar using X25519 —
 * identical output to `wg pubkey` (RFC 7748), no `wg` binary needed.
 *
 * @param {string} privB64 - base64-encoded 32-byte private key.
 * @returns {string} base64-encoded public key.
 */
function derivePubKey(privB64) {
  const raw = Buffer.from(privB64.trim(), "base64");
  if (raw.length !== 32) throw new Error("invalid WireGuard private key length");
  const privKey = crypto.createPrivateKey({
    key: Buffer.concat([X25519_PKCS8_PREFIX, raw]),
    format: "der",
    type: "pkcs8",
  });
  const pubDer = crypto.createPublicKey(privKey).export({ format: "der", type: "spki" });
  // SPKI = 12-byte algorithm prefix + raw 32-byte public point.
  return pubDer.subarray(-32).toString("base64");
}

/**
 * Ensure `/etc/wireguard/server.key` exists and return the server pubkey.
 * Prefers `wg` when available, falls back to pure-JS X25519 so `--print`
 * works before bootstrap has installed wireguard-tools.
 *
 * @returns {Promise<{ priv: string, pub: string }>}
 */
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

/**
 * Write the initial `wg0.conf` and server private key if they don't exist.
 *
 * @param {object} r - Preflight report.
 * @param {number} wgPort
 */
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

/**
 * Enable IPv4/IPv6 forwarding and persist via sysctl.d.
 */
async function ensureForwarding() {
  fs.writeFileSync(
    "/etc/sysctl.d/99-wpn.conf",
    "net.ipv4.ip_forward=1\nnet.ipv6.conf.all.forwarding=1\n"
  );
  await tryRunBin("sysctl", ["--system", "-q"]);
  log.ok("ip forwarding enabled");
}

/**
 * Bring `wg0` up via systemd (preferred) or `wg-quick` fallback.
 *
 * @param {object} r - Preflight report.
 */
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

/**
 * Ensure NAT/forwarding/clamp rules are live and persisted.
 * Uses the {@link firewall} module for backend-agnostic rule management.
 * The conf-file update is performed under the {@link confLock}.
 *
 * @param {object} r - Preflight report.
 * @returns {Promise<void>}
 */
async function ensureNat(r) {
  const added = await firewall.ensureLiveNat(r.wanIf, WG_IFACE);
  if (added) log.ok(`nat/forward/clamp rules applied (backend: ${await firewall.backend()})`);

  // Persist missing fragments — upgrades old confs in place.
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

/**
 * Run the full WireGuard bootstrap sequence.
 *
 * @param {object} r - Preflight report from `preflight.collect()`.
 * @param {{ wgPort: number, agentPort: number, echoPort?: number }} opts
 * @returns {Promise<void>}
 */
async function ensure(r, { wgPort, agentPort, echoPort }) {
  await ensureInstalled(r);
  await ensureConfig(r, wgPort);
  await ensureForwarding();
  await ensureUp(r);
  await ensureNat(r);
  await firewall.openPorts(r.ufw, wgPort, agentPort, echoPort);
}

// ---------------------------------------------------------------------------
// Conf-file peer surgery (pure functions — unit-tested)
// ---------------------------------------------------------------------------

/**
 * Extract every `[Peer]` block's PublicKey + AllowedIPs from a wg conf.
 *
 * @param {string} conf
 * @returns {Array<{ publicKey: string, allowedIps: string[] }>}
 */
function parseConfPeers(conf) {
  const peers = [];
  const blocks = conf.split(/^\s*\[/m).slice(1); // text after each "["
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

/**
 * Remove a peer (its `# wpn-peer` comment, `[Peer]` header, and body) from
 * conf content.  Returns the content unchanged if the key isn't present.
 *
 * @param {string} conf
 * @param {string} publicKey
 * @returns {string}
 */
function removePeerFromConf(conf, publicKey) {
  const lines   = conf.split("\n");
  const out     = [];
  let skipping  = false;

  for (const line of lines) {
    const t = line.trim();
    if (skipping) {
      if (t === "" ) continue;                       // swallow trailing blank
      if (t.startsWith("[") || t.startsWith("#")) skipping = false; // next block
      else continue;                                  // still inside dead block
    }
    if (t === "[Peer]") {
      // Look ahead is done implicitly: we buffer the header+comment and drop
      // them retroactively if the block contains the key.
      out.push(line);
      continue;
    }
    if (line.includes(publicKey)) {
      // Rewind: drop this block's `[Peer]` header and its `# wpn-peer` comment.
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

/**
 * Insert or replace a peer block in conf content.  Re-adding a pubkey with a
 * new address replaces the stale block instead of leaving a phantom entry
 * that would resurrect on reboot.
 *
 * @param {string} conf
 * @param {{ publicKey: string, address: string, allowedIps: string }} peer
 * @returns {string}
 */
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

// ---------------------------------------------------------------------------
// Peer management
// ---------------------------------------------------------------------------

/**
 * Validate a requested tunnel address list.
 * Every address must be a syntactically valid IPv4/IPv6 that belongs to the
 * node subnet and is not the server's own address — otherwise a peer could
 * hijack the gateway or arbitrary external IPs via cryptokey routing.
 *
 * @param {string[]} addrs
 * @throws {Error}
 */
function validatePeerAddrs(addrs) {
  const serverV4 = SUBNET_V4.split("/")[0];
  const serverV6 = normAddr(SUBNET_V6.split("/")[0]);

  for (const a of addrs) {
    const isV6 = a.includes(":");
    if (isV6 ? !expandIPv6(a) : !isValidIPv4(a)) {
      throw httpErr(400, `address ${a} is not a valid IPv4 or IPv6 address`);
    }
    if (!addrInSubnet(a, isV6 ? SUBNET_V6 : SUBNET_V4)) {
      throw httpErr(
        400,
        `address ${a} is outside the node subnet ` +
          `(${isV6 ? SUBNET_V6 : SUBNET_V4})`
      );
    }
    if (normAddr(a) === (isV6 ? serverV6 : serverV4)) {
      throw httpErr(400, `address ${a} collides with the server's own tunnel address`);
    }
  }
}

/**
 * Build the set of tunnel addresses already claimed by *other* peers,
 * looking at both the live interface and the persisted conf.
 *
 * The caller must hold {@link confLock} — the snapshot is only trustworthy
 * as a conflict check when the whole check-and-apply sequence is serialised.
 *
 * @param {string} excludeKey - Pubkey whose own addresses don't count.
 * @returns {Promise<Map<string, string>>} addr → owning pubkey.
 */
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

/**
 * Undo a live change after a persist failure: restore the peer's previous
 * allowed-ips when `prev` is given (re-add / failed removal), else remove the
 * peer.  Never throws — returns the rollback error (or null) so the caller
 * can report drift honestly.
 *
 * @param {string} publicKey
 * @param {{ allowedIps: string }|undefined} prev - Live peer before the change.
 * @returns {Promise<Error|null>}
 */
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

/**
 * Roll back the live change and build the error for a failed conf write, so
 * live state and `wg0.conf` never silently diverge.
 *
 * @param {"add"|"remove"} what
 * @param {string} publicKey
 * @param {{ allowedIps: string }|undefined} prev
 * @param {Error} cause - The persist error.
 * @returns {Promise<Error & {status: number}>}
 */
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

/**
 * Add a peer to the live WireGuard interface and persist it to `wg0.conf`.
 * Validates addresses against the node subnet, detects IP conflicts across
 * both live and persisted state, and correctly replaces an existing block on
 * re-add.  The whole claim-check → apply → persist sequence is serialised
 * through {@link confLock} so concurrent `POST /peers` calls cannot race the
 * same address onto two peers.  If the conf write fails the live change is
 * rolled back, so a retry by the control plane cannot double-add or diverge.
 *
 * @param {string} publicKey - Base64 WireGuard public key.
 * @param {string} address   - Tunnel address(es), e.g. `10.66.0.2` or `10.66.0.2,fd00:66::2`.
 * @returns {Promise<{ added: true, address: string, persisted?: boolean }>}
 * @throws {Error & {status: number}} 400 on validation failure, 409 on IP
 *   conflict, 500 on wg command or persist failure.
 */
async function addPeer(publicKey, address) {
  if (typeof publicKey !== "string" || !WG_KEY_RE.test(publicKey)) {
    throw httpErr(400, "publicKey must be a base64 WireGuard key");
  }
  if (typeof address !== "string" || !address.trim()) {
    throw httpErr(400, "address is required");
  }

  const addrs = address.split(",").map((a) => a.trim()).filter(Boolean);
  validatePeerAddrs(addrs);

  const allowedIps = addrs
    .map((a) => (a.includes(":") ? `${a}/128` : `${a}/32`))
    .join(",");

  const release = await confLock.acquire();
  try {
    // Exact-match conflict check across live + persisted state.  Done under
    // the lock: a concurrent addPeer that commits the same address before we
    // `wg set` would otherwise be invisible to this check.
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

    // Snapshot for rollback (a re-add of an existing key restores its old IPs).
    const prev = (await dump()).peers.find((p) => p.publicKey === publicKey);

    // Apply live
    await runBin("wg", [
      "set", WG_IFACE,
      "peer", publicKey,
      "allowed-ips", allowedIps,
      "persistent-keepalive", "25",
    ], { timeout: WG_SET_TIMEOUT_MS });

    // Persist.  Skipped when the conf is absent (e.g. --skip-wg dev mode —
    // the peer still lives on the interface).  A failed write rolls the live
    // change back and errors out; it never reports success for a peer that
    // would vanish on reboot.
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

/**
 * Remove a peer from the live WireGuard interface and from `wg0.conf`.
 * The live removal and the conf rewrite happen under {@link confLock}, so
 * they serialise against concurrent adds of the same key; if the conf write
 * fails the live peer is restored.
 *
 * @param {string} publicKey - Base64 WireGuard public key.
 * @returns {Promise<{ removed: true, persisted?: boolean }>}
 * @throws {Error & {status: number}} 400 on a bad key, 500 on persist failure.
 */
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
      // Only restore if there was a live peer to bring back.
      throw prev
        ? await persistFailure("remove", publicKey, prev, e)
        : httpErr(500, `failed to persist peer removal (${e.message})`);
    }
    return { removed: true };
  } finally {
    release();
  }
}

// ---------------------------------------------------------------------------
// Interface introspection
// ---------------------------------------------------------------------------

/**
 * Parse `wg show ... dump` output into peer records.
 *
 * Accepts BOTH dump layouts (the wireguard-tools C source only prefixes the
 * interface name when invoked as `wg show all dump`):
 *  - `wg show <iface> dump` → 8 fields: pubkey, psk, endpoint, allowed-ips,
 *    handshake, rx, tx, keepalive
 *  - `wg show all dump`     → 9 fields: iface, pubkey, psk, endpoint, ...
 *
 * @param {string} out    - Raw dump output.
 * @param {string} iface  - Interface name to keep peers for (9-field rows).
 * @returns {Array<{publicKey:string, endpoint:string|null, allowedIps:string, latestHandshake:number, rx:number, tx:number}>}
 */
function parseDump(out, iface) {
  const peers = [];
  for (const line of out.split("\n")) {
    const f = line.split("\t");
    let base; // index of the pubkey field
    if (f.length === 9 && f[0] === iface) base = 1;      // `all dump` row
    else if (f.length === 8)             base = 0;      // single-iface row
    else continue;                                       // iface line / garbage
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

/**
 * Query the live peer table.
 * @returns {Promise<{ peers: object[] }>}
 */
async function dump() {
  const out = await tryRunBin("wg", ["show", WG_IFACE, "dump"]);
  return { peers: out ? parseDump(out, WG_IFACE) : [] };
}

/**
 * Return aggregate statistics for the `wg0` interface.
 *
 * @returns {Promise<{ peerCount:number, activePeers:number, rxBytes:number, txBytes:number, load:number, peers: object[] }>}
 */
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

// ---------------------------------------------------------------------------
// Version cache
// ---------------------------------------------------------------------------

/** @type {Promise<string|null>|undefined} */
let _version;

/**
 * Return the installed `wireguard-tools` version string.
 * Cached — the binary version doesn't change while the agent runs.
 *
 * @returns {Promise<string|null>}
 */
function version() {
  if (_version !== undefined) return _version;
  _version = (async () => {
    const out = await tryRunBin("wg", ["--version"]);
    return (out && (out.match(/v[\d.]+/) || [])[0]) || out || null;
  })();
  return _version;
}

// ---------------------------------------------------------------------------
// Live interface facts
// ---------------------------------------------------------------------------

/**
 * Query live `wg0` state — the source of truth when `wg0` predates the agent.
 *
 * @returns {Promise<{ listenPort: number|null, subnet: string|null, address: string|null }>}
 */
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

/**
 * Return the public key of the live `wg0` interface.
 *
 * @param {string} pubFile - Path to the cached public-key file.
 * @returns {Promise<string|null>}
 */
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
  stats,
  serverPubKey,
  liveInfo,
  version,
  WG_IFACE,
  SUBNET_V4,
  SUBNET_V6,
  WG_CONF,
  // Exported for testing
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
