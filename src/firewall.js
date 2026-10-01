/**
 * @fileoverview iptables / nftables firewall abstraction.
 *
 * Detects which backend is available at startup and exposes a unified API for:
 *  - Generating PostUp/PostDown strings for `wg0.conf`
 *  - Applying and verifying live NAT + forwarding + MSS-clamp rules
 *  - Opening ports via ufw (when present)
 *
 * Detection order: iptables → nft.
 * If neither is found an error is thrown at bootstrap time (not silently ignored).
 *
 * nftables rules are written into a dedicated `inet wpn` table so they can be
 * atomically flushed on PostDown without touching any existing user rules.
 * `inet` family natively covers both IPv4 and IPv6.
 *
 * Rule set (both backends):
 *  - FORWARD in/out on the WG interface               (client traffic)
 *  - POSTROUTING MASQUERADE on the WAN interface      (NAT)
 *  - TCPMSS clamp on forwarded TCP SYNs               (PMTUD blackhole fix —
 *    without this, clients behind PPPoE/low-MTU links hang on TLS handshake)
 */

"use strict";

const { tryRun, tryRunBin, log } = require("./util");

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

/** @type {"iptables"|"nftables"|null|undefined} undefined = not yet detected */
let _backend = undefined;

/**
 * Return the available firewall backend.
 *
 * @returns {Promise<"iptables"|"nftables">}
 * @throws {Error} if neither iptables nor nft is available.
 */
async function backend() {
  if (_backend !== undefined) return _backend;
  if (await tryRun("command -v iptables")) { _backend = "iptables"; return _backend; }
  if (await tryRun("command -v nft"))      { _backend = "nftables"; return _backend; }
  throw new Error(
    "no firewall backend found — install iptables or nftables before running the agent"
  );
}

// ---------------------------------------------------------------------------
// Rule fragments
// ---------------------------------------------------------------------------

/**
 * @typedef {{ up: string, down: string, key: string, add?: string, check?: string }} Fragment
 * `key` is a distinctive substring used to detect whether the fragment is
 * already present in a conf file or live ruleset — enables incremental
 * patching of confs written by older agent versions.
 *
 * iptables fragments additionally carry `add` (plain append, no shell
 * suffix) and `check` (the matching `-C` existence test) — built from one
 * structured definition, never derived from `up` by string surgery.
 */

/**
 * Build one iptables-family rule from a single definition so its append,
 * delete and check forms can never disagree.
 *
 * @param {"iptables"|"ip6tables"} bin
 * @param {"filter"|"nat"|"mangle"} table
 * @param {string} chain
 * @param {string} spec  - Match + target, e.g. `-i wg0 -j ACCEPT`.
 * @param {boolean} [soft] - Embed with `|| true` (v6 may be unavailable).
 * @returns {{ up: string, down: string, add: string, check: string }}
 */
function iptRule(bin, table, chain, spec, soft = false) {
  const t   = table === "filter" ? "" : `-t ${table} `;
  const cmd = (op) => `${bin} ${t}${op} ${chain} ${spec}`;
  const wrap = (c) => (soft ? `${c} 2>/dev/null || true` : c);
  return { up: wrap(cmd("-A")), down: wrap(cmd("-D")), add: cmd("-A"), check: cmd("-C") };
}

/**
 * Ordered list of rule fragments for a backend.
 *
 * @param {"iptables"|"nftables"} b
 * @param {string} wanIf   - WAN interface name (e.g. `"eth0"`).
 * @param {string} wgIface - WireGuard interface name (e.g. `"wg0"`).
 * @returns {Fragment[]}
 */
function fragments(b, wanIf, wgIface) {
  if (b === "iptables") {
    const clamp = "-p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu";
    return [
      { key: `iptables -A FORWARD -i ${wgIface}`,
        ...iptRule("iptables", "filter", "FORWARD", `-i ${wgIface} -j ACCEPT`) },
      { key: `iptables -A FORWARD -o ${wgIface}`,
        ...iptRule("iptables", "filter", "FORWARD", `-o ${wgIface} -j ACCEPT`) },
      { key: `MASQUERADE`,
        ...iptRule("iptables", "nat", "POSTROUTING", `-o ${wanIf} -j MASQUERADE`) },
      { key: `TCPMSS`,
        ...iptRule("iptables", "mangle", "FORWARD", clamp) },
      { key: `ip6tables -A FORWARD -i ${wgIface}`,
        ...iptRule("ip6tables", "filter", "FORWARD", `-i ${wgIface} -j ACCEPT`, true) },
      { key: `ip6tables -A FORWARD -o ${wgIface}`,
        ...iptRule("ip6tables", "filter", "FORWARD", `-o ${wgIface} -j ACCEPT`, true) },
      { key: `ip6tables -t nat -A POSTROUTING`,
        ...iptRule("ip6tables", "nat", "POSTROUTING", `-o ${wanIf} -j MASQUERADE`, true) },
      { key: `ip6tables -t mangle`,
        ...iptRule("ip6tables", "mangle", "FORWARD", clamp, true) },
    ];
  }

  // nftables: dedicated `inet wpn` table, dual-stack, atomic teardown.
  const mssClamp =
    `nft add rule inet wpn forward ` +
    `'tcp flags syn / syn,rst tcp option maxseg size set rt mtu'`;
  return [
    {
      key:  `inet wpn`,
      up:   `nft add table inet wpn`,
      down: `nft delete table inet wpn`,
    },
    {
      key:  `inet wpn forward`,
      up:
        `nft add chain inet wpn forward ` +
        `'{ type filter hook forward priority 0; policy accept; }'; ` +
        `nft add rule inet wpn forward iifname "${wgIface}" accept; ` +
        `nft add rule inet wpn forward oifname "${wgIface}" accept`,
      down: ``,
    },
    {
      key:  `inet wpn postrouting`,
      up:
        `nft add chain inet wpn postrouting ` +
        `'{ type nat hook postrouting priority 100; }'; ` +
        `nft add rule inet wpn postrouting oifname "${wanIf}" masquerade`,
      down: ``,
    },
    {
      key:  `maxseg`,
      up:   mssClamp,
      down: ``,
    },
  ];
}

// ---------------------------------------------------------------------------
// PostUp / PostDown strings for wg0.conf
// ---------------------------------------------------------------------------

/**
 * Return the PostUp/PostDown shell commands to embed in `wg0.conf`.
 *
 * @param {string} wanIf   - WAN interface name (e.g. `"eth0"`).
 * @param {string} wgIface - WireGuard interface name (e.g. `"wg0"`).
 * @param {"iptables"|"nftables"} [b] - Backend override (testing); auto-detected
 *   when omitted.
 * @returns {Promise<{ up: string, down: string }>}
 */
async function confNatRules(wanIf, wgIface, b) {
  const be = b || (await backend());
  const parts = fragments(be, wanIf, wgIface);
  return {
    up:   parts.map((p) => p.up).filter(Boolean).join("; "),
    down: parts.map((p) => p.down).filter(Boolean).join("; "),
  };
}

// ---------------------------------------------------------------------------
// Live rule management
// ---------------------------------------------------------------------------

/**
 * Ensure NAT, forwarding, and MSS-clamp rules are applied to the running
 * kernel.  Idempotent — checks before adding; re-asserts missing rules so it
 * also serves as a self-heal when something else flushes the tables.
 *
 * @param {string} wanIf
 * @param {string} wgIface
 * @param {"iptables"|"nftables"} [b] - Backend override (testing).
 * @returns {Promise<number>} Number of rules that were newly applied.
 */
async function ensureLiveNat(wanIf, wgIface, b) {
  const be = b || (await backend());

  if (be === "iptables") {
    let added = 0;
    for (const f of fragments("iptables", wanIf, wgIface)) {
      if ((await tryRun(f.check)) !== null) continue; // already present
      // Count only rules that actually landed (ip6tables may be unavailable —
      // that must not read as "rules were missing" on every health poll).
      if ((await tryRun(`${f.add} 2>/dev/null`)) !== null) added++;
    }
    return added;
  }

  // nftables: check for table existence; build if absent.  Missing clamp on
  // an older table is patched incrementally.
  const tableExists = (await tryRunBin("nft", ["list", "table", "inet", "wpn"])) !== null;
  if (tableExists) {
    const ruleset = (await tryRunBin("nft", ["list", "table", "inet", "wpn"])) || "";
    if (!ruleset.includes("maxseg")) {
      await tryRun(
        `nft add rule inet wpn forward ` +
          `tcp flags syn / syn,rst tcp option maxseg size set rt mtu`
      );
      return 1;
    }
    return 0;
  }

  const parts = fragments("nftables", wanIf, wgIface);
  for (const f of parts) {
    for (const cmd of f.up.split("; ")) {
      // Strip the shell quoting used for conf embedding — nft args with
      // single-quoted sets still work via /bin/sh.
      await tryRun(cmd);
    }
  }
  return 1;
}

/**
 * Persist missing NAT/clamp fragments into `wg0.conf`.
 * Each fragment is checked individually by its `key` substring, so confs
 * written by older agent versions (e.g. without MSS clamping) get patched
 * incrementally instead of skipped wholesale.
 *
 * Caller is responsible for writing the result with the conf-file lock held.
 *
 * @param {string} conf    - Current `wg0.conf` content.
 * @param {string} wanIf
 * @param {string} wgIface
 * @param {"iptables"|"nftables"} [b] - Backend override (testing).
 * @returns {Promise<string>} Updated conf content.
 */
async function patchConfNat(conf, wanIf, wgIface, b) {
  const be = b || (await backend());
  const parts = fragments(be, wanIf, wgIface);

  const missingUp   = parts.filter((f) => f.up   && !conf.includes(f.key)).map((f) => f.up);
  const missingDown = parts.filter((f) => f.down && !conf.includes(f.key)).map((f) => f.down);

  if (!missingUp.length && !missingDown.length) return conf;

  const upJoin   = missingUp.join("; ");
  const downJoin = missingDown.filter(Boolean).join("; ");

  if (/^PostUp\s*=/m.test(conf)) {
    if (upJoin) conf = conf.replace(/^(PostUp\s*=.*)$/m, `$1; ${upJoin}`);
    if (downJoin) {
      conf = /^PostDown\s*=/m.test(conf)
        ? conf.replace(/^(PostDown\s*=.*)$/m, `$1; ${downJoin}`)
        : conf.replace(/^(PostUp\s*=.*)$/m, `$1\nPostDown = ${downJoin}`);
    }
  } else {
    conf = conf.replace(
      /^(PrivateKey\s*=.*)$/m,
      `$1\nPostUp = ${upJoin}` + (downJoin ? `\nPostDown = ${downJoin}` : "")
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
 * @param {number}  [echoPort]   - UDP echo probe port.
 * @param {number}  [stealthPort]- wstunnel port, when stealth is enabled.
 */
async function openPorts(ufw, wgPort, agentPort, echoPort, stealthPort) {
  if (!ufw) return;
  await tryRunBin("ufw", ["allow", `${wgPort}/udp`]);
  await tryRunBin("ufw", ["allow", `${agentPort}/tcp`]);
  if (echoPort)   await tryRunBin("ufw", ["allow", `${echoPort}/udp`]);
  if (stealthPort) await tryRunBin("ufw", ["allow", `${stealthPort}/tcp`]);
  log.ok(
    `ufw: opened udp/${wgPort} tcp/${agentPort}` +
      (echoPort ? ` udp/${echoPort}` : "") +
      (stealthPort ? ` tcp/${stealthPort}` : "")
  );
}

module.exports = { backend, confNatRules, ensureLiveNat, patchConfNat, openPorts };
