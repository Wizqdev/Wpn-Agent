"use strict";

const test = require("node:test");
const assert = require("node:assert");
const { confNatRules, patchConfNat } = require("../src/firewall");

// Backend is injected so these run on hosts without iptables/nft (macOS CI).

test("firewall - iptables rules include NAT, forward, and MSS clamp", async () => {
  const { up, down } = await confNatRules("eth0", "wg0", "iptables");
  assert.ok(up.includes("iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE"));
  assert.ok(up.includes("iptables -A FORWARD -i wg0 -j ACCEPT"));
  assert.ok(up.includes("iptables -A FORWARD -o wg0 -j ACCEPT"));
  // PMTUD blackhole fix — clamp MSS on forwarded SYNs.
  assert.ok(up.includes("TCPMSS --clamp-mss-to-pmtu"));
  assert.ok(up.includes("ip6tables -t nat -A POSTROUTING"));
  assert.ok(down.includes("iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE"));
  assert.ok(down.includes("TCPMSS"));
});

test("firewall - nftables uses dedicated `inet wpn` table with clamp", async () => {
  const { up, down } = await confNatRules("eth0", "wg0", "nftables");
  assert.ok(up.includes("nft add table inet wpn"));
  assert.ok(up.includes("masquerade"));
  assert.ok(up.includes("maxseg size set rt mtu"));
  assert.strictEqual(down, "nft delete table inet wpn");
});

test("firewall - patchConfNat adds rules to a bare conf", async () => {
  const conf = "[Interface]\nPrivateKey = X\n";
  const out = await patchConfNat(conf, "eth0", "wg0", "iptables");
  assert.ok(out.includes("PostUp ="));
  assert.ok(out.includes("PostDown ="));
  assert.ok(out.includes("MASQUERADE"));
  assert.ok(out.includes("TCPMSS"));
});

test("firewall - patchConfNat is idempotent on a current conf", async () => {
  const { up, down } = await confNatRules("eth0", "wg0", "iptables");
  const conf = `[Interface]\nPrivateKey = X\nPostUp = ${up}\nPostDown = ${down}\n`;
  const out = await patchConfNat(conf, "eth0", "wg0", "iptables");
  assert.strictEqual(out, conf); // nothing to patch
});

test("firewall - patchConfNat upgrades an old conf missing the clamp", async () => {
  // Simulate a conf written before MSS clamping existed.
  const conf =
    "[Interface]\n" +
    "PrivateKey = X\n" +
    "PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE\n" +
    "PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE\n";
  const out = await patchConfNat(conf, "eth0", "wg0", "iptables");
  // NAT fragments detected as present; clamp fragments appended.
  assert.ok(out.includes("TCPMSS --clamp-mss-to-pmtu"));
  assert.ok(out.includes("ip6tables -t mangle"));
  // Existing rules kept, only one MASQUERADE add.
  assert.strictEqual(out.split("MASQUERADE").length - 1 >= 2, true);
});

// ---------------------------------------------------------------------------
// ensureLiveNat — explicit check commands, add-if-missing idempotence.
// ---------------------------------------------------------------------------

const util = require("../src/util");
const firewall = require("../src/firewall");

/** Fake iptables: tracks the live rule set; -C fails when a rule is absent. */
function fakeIptables({ failV6 = false } = {}) {
  const rules = new Set();
  const adds  = [];
  const norm  = (cmd) =>
    cmd.replace(/ -[ACD] /, " -X ").replace(/\s*2>\/dev\/null( \|\| true)?$/, "");
  util.setRunner({
    async run(cmd) {
      if (failV6 && cmd.startsWith("ip6tables")) throw new Error("ip6tables unavailable");
      if (/ -C /.test(cmd)) {
        if (rules.has(norm(cmd))) return "";
        throw new Error("rule missing");
      }
      if (/ -A /.test(cmd)) { rules.add(norm(cmd)); adds.push(cmd); return ""; }
      throw new Error(`unexpected command: ${cmd}`);
    },
  });
  return { rules, adds };
}

test("firewall - every iptables fragment has an explicit -C check and plain -A add", async () => {
  const frags = [];
  // fragments() is internal; reach it through confNatRules' backend contract.
  const { up } = await confNatRules("eth0", "wg0", "iptables");
  assert.ok(up.length > 0);
  util.setRunner({
    async run(cmd) { frags.push(cmd); throw new Error("force add path"); },
  });
  try {
    await firewall.ensureLiveNat("eth0", "wg0", "iptables");
  } finally {
    util.resetRunner();
  }
  const checks = frags.filter((c) => / -C /.test(c));
  const adds   = frags.filter((c) => / -A /.test(c));
  assert.strictEqual(checks.length, 8, "one -C per fragment");
  assert.strictEqual(adds.length, 8, "one -A per fragment");
  for (const c of checks) assert.ok(!/ -A /.test(c), `check must not contain -A: ${c}`);
});

test("firewall - ensureLiveNat adds each rule exactly once across repeated polls", async () => {
  const fake = fakeIptables();
  try {
    const first  = await firewall.ensureLiveNat("eth0", "wg0", "iptables");
    const second = await firewall.ensureLiveNat("eth0", "wg0", "iptables");
    const third  = await firewall.ensureLiveNat("eth0", "wg0", "iptables");
    assert.deepStrictEqual([first, second, third], [8, 0, 0]);
    assert.strictEqual(fake.adds.length, 8, "no duplicate appends");
    assert.strictEqual(fake.rules.size, 8);
  } finally { util.resetRunner(); }
});

test("firewall - re-asserts only the rule that was flushed", async () => {
  const fake = fakeIptables();
  try {
    await firewall.ensureLiveNat("eth0", "wg0", "iptables");
    const masq = [...fake.rules].find((r) => r.startsWith("iptables -t nat -X POSTROUTING"));
    assert.ok(masq);
    fake.rules.delete(masq); // something flushed NAT
    assert.strictEqual(await firewall.ensureLiveNat("eth0", "wg0", "iptables"), 1);
    assert.strictEqual(fake.rules.size, 8);
  } finally { util.resetRunner(); }
});

test("firewall - unavailable ip6tables does not read as 'rules missing' every poll", async () => {
  fakeIptables({ failV6: true });
  try {
    assert.strictEqual(await firewall.ensureLiveNat("eth0", "wg0", "iptables"), 4); // v4 only
    assert.strictEqual(await firewall.ensureLiveNat("eth0", "wg0", "iptables"), 0);
  } finally { util.resetRunner(); }
});
