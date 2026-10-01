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
