
"use strict";

const { tryRun, tryRunBin, log } = require("./util");

let _backend = undefined;

async function backend() {
  if (_backend !== undefined) return _backend;
  if (await tryRun("command -v iptables")) { _backend = "iptables"; return _backend; }
  if (await tryRun("command -v nft"))      { _backend = "nftables"; return _backend; }
  throw new Error(
    "no firewall backend found — install iptables or nftables before running the agent"
  );
}

function iptRule(bin, table, chain, spec, soft = false) {
  const t   = table === "filter" ? "" : `-t ${table} `;
  const cmd = (op) => `${bin} ${t}${op} ${chain} ${spec}`;
  const wrap = (c) => (soft ? `${c} 2>/dev/null || true` : c);
  return { up: wrap(cmd("-A")), down: wrap(cmd("-D")), add: cmd("-A"), check: cmd("-C") };
}

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


async function confNatRules(wanIf, wgIface, b) {
  const be = b || (await backend());
  const parts = fragments(be, wanIf, wgIface);
  return {
    up:   parts.map((p) => p.up).filter(Boolean).join("; "),
    down: parts.map((p) => p.down).filter(Boolean).join("; "),
  };
}

async function ensureLiveNat(wanIf, wgIface, b) {
  const be = b || (await backend());

  if (be === "iptables") {
    let added = 0;
    for (const f of fragments("iptables", wanIf, wgIface)) {
      if ((await tryRun(f.check)) !== null) continue;

      if ((await tryRun(`${f.add} 2>/dev/null`)) !== null) added++;
    }
    return added;
  }

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

      await tryRun(cmd);
    }
  }
  return 1;
}

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
