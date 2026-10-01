"use strict";

const test = require("node:test");
const assert = require("node:assert");
const net = require("net");
const { pickPort, canBind } = require("../src/stealth");

test("stealth - pickPort falls back when the first port is occupied", async () => {
  const blocker = net.createServer();

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

const fs   = require("fs");
const os   = require("os");
const path = require("path");
const util = require("../src/util");
const stealth = require("../src/stealth");

const P1 = 28450;
const P2 = 28451;

function harness() {
  const dir  = fs.mkdtempSync(path.join(os.tmpdir(), "wpn-stealth-"));
  const bin  = path.join(dir, "wstunnel");
  fs.writeFileSync(bin, "");
  const state = { active: false, calls: [] };
  util.setRunner({
    async runBin(b, args) {
      assert.strictEqual(b, "systemctl");
      state.calls.push(args.join(" "));
      if (args[0] === "is-active") {
        if (state.active) return "active";
        throw new Error("inactive");
      }
      if (args[0] === "enable" || args[0] === "restart") state.active = true;
      return "";
    },
  });
  const deps = {
    platform: "linux",
    unit: path.join(dir, "wpn-stealth.service"),
    bin,
    candidates: [P1, P2],
    settleMs: 0,
    probe: async () => true,
  };
  const cleanup = () => { util.resetRunner(); fs.rmSync(dir, { recursive: true, force: true }); };
  return { dir, deps, state, cleanup };
}

const listen = (port) => new Promise((resolve) => {
  const s = net.createServer();
  s.listen(port, "0.0.0.0", () => resolve(s));
});

test("stealth - first start picks the preferred port and writes a hardened, root-only unit", async () => {
  const h = harness();
  try {
    const r = await stealth.ensure(h.dir, { wgPort: 51820 }, h.deps);
    assert.deepStrictEqual([r.enabled, r.port], [true, P1]);
    const unit = fs.readFileSync(h.deps.unit, "utf8");
    assert.match(unit, new RegExp(`server wss://0\\.0\\.0\\.0:${P1} `));
    assert.match(unit, /NoNewPrivileges=true/);
    assert.strictEqual(fs.statSync(h.deps.unit).mode & 0o777, 0o600);
  } finally { h.cleanup(); }
});

test("stealth - restart while the relay holds the port keeps the advertised port", async () => {
  const h = harness();
  try {
    await stealth.ensure(h.dir, { wgPort: 51820 }, h.deps);
    const relay = await listen(P1);
    try {
      h.state.calls.length = 0;
      const r = await stealth.ensure(h.dir, { wgPort: 51820 }, h.deps);
      assert.deepStrictEqual([r.enabled, r.port], [true, P1], "must NOT fall back to P2");
      assert.strictEqual(readPort(h.deps.unit), P1, "unit must still point at P1");
      assert.ok(!h.state.calls.includes("restart wpn-stealth"), "unchanged unit must not restart");
    } finally { relay.close(); }
  } finally { h.cleanup(); }
});

test("stealth - a changed unit restarts the running relay", async () => {
  const h = harness();
  try {
    await stealth.ensure(h.dir, { wgPort: 51820 }, h.deps);
    const relay = await listen(P1);
    try {
      h.state.calls.length = 0;
      const r = await stealth.ensure(h.dir, { wgPort: 51999 }, h.deps);
      assert.strictEqual(r.port, P1);
      assert.ok(h.state.calls.includes("restart wpn-stealth"), "explicit restart required");
      assert.match(fs.readFileSync(h.deps.unit, "utf8"), /--restrict-to 127\.0\.0\.1:51999/);
    } finally { relay.close(); }
  } finally { h.cleanup(); }
});

test("stealth - preferred port taken by another process falls back", async () => {
  const h = harness();
  const other = await listen(P1);
  try {
    const r = await stealth.ensure(h.dir, { wgPort: 51820 }, h.deps);
    assert.deepStrictEqual([r.enabled, r.port], [true, P2]);
  } finally { other.close(); h.cleanup(); }
});

test("stealth - active unit that is not listening is reported as failed", async () => {
  const h = harness();
  try {
    const r = await stealth.ensure(h.dir, { wgPort: 51820 }, { ...h.deps, probe: async () => false });
    assert.strictEqual(r.enabled, false);
    assert.match(r.error, /nothing is listening/);
  } finally { h.cleanup(); }
});

test("stealth - inactive unit after start is reported as failed", async () => {
  const h = harness();
  try {
    util.setRunner({ async runBin() { throw new Error("nope"); } });
    const r = await stealth.ensure(h.dir, { wgPort: 51820 }, h.deps);
    assert.strictEqual(r.enabled, false);
    assert.match(r.error, /unit is/);
  } finally { h.cleanup(); }
});

function readPort(unitPath) {
  return stealth.readUnitPort(unitPath);
}
