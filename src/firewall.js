/**
 * @fileoverview iptables / nftables firewall abstraction.
 *
 * Detects which backend is available at startup and exposes a unified API for:
 *  - Generating PostUp/PostDown strings for `wg0.conf`
 *  - Applying and verifying live NAT + forwarding rules
 *  - Opening ports via ufw (when present)
 *
 *
 * Detection order: iptables → nft.
 * If neither is found an error is thrown at bootstrap time (not silently ignored).
 *
 * nftables rules are written into a dedicated `inet wpn` table so they can be
 * atomically flushed on PostDown without touching any existing user rules.
 * `inet` family natively covers both IPv4 and IPv6.
 */

"use strict";

const { tryRun, log } = require("./util");

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

/** @type {"iptables"|"nftables"|null} */
let _backend = undefined; // undefined = not yet detected

/**
 * Return the available firewall backend.
 *
 * @returns {"iptables"|"nftables"}
 * @throws {Error} if neither iptables nor nft is available.
 */
function backend() {
  if (_backend !== undefined) return _backend;
  if (tryRun("command -v iptables")) { _backend = "iptables"; return _backend; }
  if (tryRun("command -v nft"))      { _backend = "nftables"; return _backend; }
  throw new Error(
    "no firewall backend found — install iptables or nftables before running the agent"
  );
}

// ---------------------------------------------------------------------------
// PostUp / PostDown strings for wg0.conf
// ---------------------------------------------------------------------------

/**
 * @typedef {{ up: string, down: string }} NatRules
 */

/**
 * Return the PostUp/PostDown shell commands to embed in `wg0.conf`.
 *
 * @param {string} wanIf  - WAN interface name (e.g. `"eth0"`).
 * @param {string} wgIface - WireGuard interface name (e.g. `"wg0"`).
 * @returns {NatRules}
 */
function confNatRules(wanIf, wgIface) {
  const b = backend();

  if (b === "iptables") {
    const fwd = `FORWARD -i ${wgIface} -j ACCEPT`;
    const fwo = `FORWARD -o ${wgIface} -j ACCEPT`;
    const nat = `POSTROUTING -o ${wanIf} -j MASQUERADE`;
    return {
      up:   `iptables -A ${fwd}; iptables -A ${fwo}; iptables -t nat -A ${nat}; ip6tables -A ${fwd} 2>/dev/null || true; ip6tables -A ${fwo} 2>/dev/null || true; ip6tables -t nat -A ${nat} 2>/dev/null || true`,
      down: `iptables -D ${fwd}; iptables -D ${fwo}; iptables -t nat -D ${nat}; ip6tables -D ${fwd} 2>/dev/null || true; ip6tables -D ${fwo} 2>/dev/null || true; ip6tables -t nat -D ${nat} 2>/dev/null || true`,
    };
  }

  // nftables: use a dedicated `inet wpn` table for dual-stack.
  return {
    up: [
      `nft add table inet wpn`,
      `nft add chain inet wpn forward '{ type filter hook forward priority 0; policy accept; }'`,
      `nft add rule  inet wpn forward iifname "${wgIface}" accept`,
      `nft add rule  inet wpn forward oifname "${wgIface}" accept`,
      `nft add chain inet wpn postrouting '{ type nat hook postrouting priority 100; }'`,
      `nft add rule  inet wpn postrouting oifname "${wanIf}" masquerade`,
    ].join("; "),
    down: `nft delete table inet wpn`,
  };
}

// ---------------------------------------------------------------------------
// Live rule management
// ---------------------------------------------------------------------------

/**
 * Ensure the NAT and forwarding rules are applied to the running kernel.
 * Idempotent for iptables (checks before adding); uses flush+rebuild for nftables.
 *
 * @param {string} wanIf
 * @param {string} wgIface
 * @returns {number} Number of rules that were newly applied.
 */
function ensureLiveNat(wanIf, wgIface) {
  const b = backend();

  if (b === "iptables") {
    const checks = [
      { c: `iptables -C FORWARD -i ${wgIface} -j ACCEPT`,         a: `iptables -A FORWARD -i ${wgIface} -j ACCEPT` },
      { c: `iptables -C FORWARD -o ${wgIface} -j ACCEPT`,         a: `iptables -A FORWARD -o ${wgIface} -j ACCEPT` },
      { c: `iptables -t nat -C POSTROUTING -o ${wanIf} -j MASQUERADE`, a: `iptables -t nat -A POSTROUTING -o ${wanIf} -j MASQUERADE` },
      { c: `ip6tables -C FORWARD -i ${wgIface} -j ACCEPT`,        a: `ip6tables -A FORWARD -i ${wgIface} -j ACCEPT` },
      { c: `ip6tables -C FORWARD -o ${wgIface} -j ACCEPT`,        a: `ip6tables -A FORWARD -o ${wgIface} -j ACCEPT` },
      { c: `ip6tables -t nat -C POSTROUTING -o ${wanIf} -j MASQUERADE`, a: `ip6tables -t nat -A POSTROUTING -o ${wanIf} -j MASQUERADE` },
    ];
    let added = 0;
    for (const { c, a } of checks) {
      if (tryRun(c) === null) { tryRun(`${a} 2>/dev/null`); added++; }
    }
    return added;
  }

  // nftables: check for table existence; build if absent.
  const tableExists = tryRun("nft list table inet wpn") !== null;
  if (tableExists) return 0;

  const rules = confNatRules(wanIf, wgIface);
  // Execute each clause individually (split on "; ").
  for (const cmd of rules.up.split("; ")) tryRun(cmd);
  return 1;
}

/**
 * Persist NAT rules into `wg0.conf` if they aren't already present.
 * Reads the existing conf, patches PostUp/PostDown, and returns the new content
 * (caller is responsible for writing with the conf-file lock held).
 *
 * @param {string} conf    - Current `wg0.conf` content.
 * @param {string} wanIf
 * @param {string} wgIface
 * @returns {string} Updated conf content (may be unchanged if already present).
 */
function patchConfNat(conf, wanIf, wgIface) {
  const sentinel = backend() === "iptables" ? "MASQUERADE" : "inet wpn";
  if (conf.includes(sentinel)) return conf; // already patched

  const { up, down } = confNatRules(wanIf, wgIface);

  if (/^PostUp\s*=/m.test(conf)) {
    conf = conf.replace(/^(PostUp\s*=.*)$/m, `$1; ${up}`);
    conf = /^PostDown\s*=/m.test(conf)
      ? conf.replace(/^(PostDown\s*=.*)$/m, `$1; ${down}`)
      : conf.replace(/^(PostUp\s*=.*)$/m, `$1\nPostDown = ${down}`);
  } else {
    conf = conf.replace(
      /^(PrivateKey\s*=.*)$/m,
      `$1\nPostUp = ${up}\nPostDown = ${down}`
    );
  }
  return conf;
}

// ---------------------------------------------------------------------------
// UFW
// ---------------------------------------------------------------------------

/**
 * Open the required ports in ufw if it is installed.
 *
 * @param {boolean} ufw - Whether ufw is present (from preflight report).
 * @param {number}  wgPort
 * @param {number}  agentPort
 */
function openPorts(ufw, wgPort, agentPort) {
  if (!ufw) return;
  tryRun(`ufw allow ${wgPort}/udp`);
  tryRun(`ufw allow ${agentPort}/tcp`);
  log.ok(`ufw: opened udp/${wgPort} + tcp/${agentPort}`);
}

module.exports = { backend, confNatRules, ensureLiveNat, patchConfNat, openPorts };
