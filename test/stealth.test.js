"use strict";

const test = require("node:test");
const assert = require("node:assert");
const net = require("net");
const { pickPort, canBind } = require("../src/stealth");

// pickPort is exercised with high ports — 443/8443 need root on POSIX.

test("stealth - pickPort falls back when the first port is occupied", async () => {
  const blocker = net.createServer();
  // Bind the wildcard addr — matching what canBind probes (SO_REUSEADDR on
  // BSD allows wildcard-after-specific coexistence, which would mask the bug).
  await new Promise((r) => blocker.listen(28443, "0.0.0.0", r));
  try {
    const picked = await pickPort([28443, 28444]);
    assert.strictEqual(picked, 28444, "must skip the busy port");
  } finally {
    blocker.close();
  }
});

test("stealth - canBind reports a busy port as false", async () => {
  const blocker = net.createServer();
  await new Promise((r) => blocker.listen(28445, "0.0.0.0", r));
  try {
    assert.strictEqual(await canBind(28445), false);
    assert.strictEqual(await canBind(28446), true);
  } finally {
    blocker.close();
  }
});
