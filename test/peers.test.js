"use strict";

// Peer-management tests against a fake `wg` and a temp wg0.conf.  The conf
// path must be set BEFORE the module is loaded (it is read at require time).

const test   = require("node:test");
const assert = require("node:assert");
const fs     = require("fs");
const os     = require("os");
const path   = require("path");

const tmp  = fs.mkdtempSync(path.join(os.tmpdir(), "wpn-peers-"));
const CONF = path.join(tmp, "wg0.conf");
process.env.WPN_WG_CONF = CONF;

const util     = require("../src/util");
const wg       = require("../src/wireguard");
const { confLock } = require("../src/lock");

const INITIAL = "[Interface]\nAddress = 10.66.0.1/24\nPrivateKey = X\n\n";
const tick    = () => new Promise((r) => setImmediate(r));

/** Fake kernel peer table: pubkey -> allowed-ips string. */
const live = new Map();
let wgSetCalls = 0;

util.setRunner({
  async runBin(bin, args) {
    assert.strictEqual(bin, "wg");
    if (args[0] === "show" && args[2] === "dump") {
      await tick();
      const iface = "priv\tpub\t51820\toff";
      const rows  = [...live].map(([k, ips]) => `${k}\t(none)\t(none)\t${ips}\t0\t0\t0\t25`);
      return [iface, ...rows].join("\n");
    }
    if (args[0] === "set") {
      wgSetCalls++;
      await tick(); // widen the race window — without the lock this interleaves
      await tick();
      const key = args[3];
      if (args[4] === "remove") live.delete(key);
      else live.set(key, args[args.indexOf("allowed-ips") + 1]);
      return "";
    }
    throw new Error(`unexpected wg call: ${args.join(" ")}`);
  },
});

test.before(() => fs.writeFileSync(CONF, INITIAL, { mode: 0o600 }));
test.after(() => {
  util.resetRunner();
  fs.rmSync(tmp, { recursive: true, force: true });
});

const key = () => wg._genKeyPair().pub;

/** conf + live state as comparable key -> sorted bare-IP list. */
function snapshots() {
  const norm = (list) => list.map((s) => s.split("/")[0]).sort().join(",");
  const confMap = new Map(
    wg._parseConfPeers(fs.readFileSync(CONF, "utf8")).map((p) => [p.publicKey, norm(p.allowedIps)])
  );
  const liveMap = new Map([...live].map(([k, v]) => [k, norm(v.split(","))]));
  return { confMap, liveMap };
}

function assertConsistentAndUnique() {
  const { confMap, liveMap } = snapshots();
  assert.deepStrictEqual([...confMap].sort(), [...liveMap].sort(), "conf and live diverged");
  const seen = new Set();
  for (const ips of liveMap.values()) {
    for (const ip of ips.split(",")) {
      assert.ok(!seen.has(ip), `IP ${ip} assigned to two peers`);
      seen.add(ip);
    }
  }
}

test("peers - parallel adds: one winner per contested IP, no drift", async () => {
  const contested = Array.from({ length: 10 }, key);
  const same      = key();
  const distinct  = Array.from({ length: 20 }, (_, i) => [key(), `10.66.0.${100 + i}`]);

  const jobs = [
    ...contested.map((k) => wg.addPeer(k, "10.66.0.50").then(() => "ok", (e) => e)),
    wg.addPeer(same, "10.66.0.60").then(() => "ok", (e) => e),
    wg.addPeer(same, "10.66.0.61").then(() => "ok", (e) => e),
    ...distinct.map(([k, ip]) => wg.addPeer(k, ip).then(() => "ok", (e) => e)),
  ];
  const res = await Promise.all(jobs);

  const contestRes = res.slice(0, 10);
  assert.strictEqual(contestRes.filter((r) => r === "ok").length, 1, "exactly one winner");
  for (const r of contestRes.filter((r) => r !== "ok")) {
    assert.strictEqual(r.status, 409, `loser should get 409, got ${r.status}: ${r.message}`);
  }
  assert.deepStrictEqual(res.slice(10, 12), ["ok", "ok"], "same key re-add (new IP) succeeds twice");
  assert.ok(res.slice(12).every((r) => r === "ok"), "distinct peers all succeed");

  assertConsistentAndUnique();
  assert.strictEqual([...live.keys()].filter((k) => k === same).length, 1);
});

test("peers - validation errors are 400s", async () => {
  await assert.rejects(wg.addPeer("nope", "10.66.0.9"), (e) => e.status === 400);
  await assert.rejects(wg.addPeer(key(), ""), (e) => e.status === 400);
  await assert.rejects(wg.addPeer(key(), "192.168.1.1"), (e) => e.status === 400);
  await assert.rejects(wg.addPeer(key(), "10.66.0.1"), (e) => e.status === 400);
  await assert.rejects(wg.removePeer("nope"), (e) => e.status === 400);
});

test("peers - persist failure on add rolls back the live peer", async () => {
  const k = key();
  const before = fs.readFileSync(CONF, "utf8");
  fs.mkdirSync(`${CONF}.tmp`); // makes the atomic write fail (EISDIR) even as root
  try {
    await assert.rejects(wg.addPeer(k, "10.66.0.200"), (e) => e.status === 500 && /rolled back/.test(e.message));
  } finally {
    fs.rmdirSync(`${CONF}.tmp`);
  }
  assert.ok(!live.has(k), "peer must not stay live after a failed persist");
  assert.strictEqual(fs.readFileSync(CONF, "utf8"), before, "conf untouched");
  assertConsistentAndUnique();
  // A retry now succeeds cleanly — no phantom IP claim left behind.
  await wg.addPeer(k, "10.66.0.200");
  assertConsistentAndUnique();
});

test("peers - persist failure on re-add restores the previous address", async () => {
  const k = key();
  await wg.addPeer(k, "10.66.0.210");
  fs.mkdirSync(`${CONF}.tmp`);
  try {
    await assert.rejects(wg.addPeer(k, "10.66.0.211"), (e) => e.status === 500);
  } finally {
    fs.rmdirSync(`${CONF}.tmp`);
  }
  assert.strictEqual(live.get(k), "10.66.0.210/32", "old allowed-ips restored live");
  assertConsistentAndUnique();
});

test("peers - persist failure on remove restores the live peer", async () => {
  const k = key();
  await wg.addPeer(k, "10.66.0.220");
  fs.mkdirSync(`${CONF}.tmp`);
  try {
    await assert.rejects(wg.removePeer(k), (e) => e.status === 500);
  } finally {
    fs.rmdirSync(`${CONF}.tmp`);
  }
  assert.ok(live.has(k), "peer restored live after failed removal persist");
  assertConsistentAndUnique();
  await wg.removePeer(k);
  assert.ok(!live.has(k));
  assertConsistentAndUnique();
});

test("peers - add/remove/add completes without deadlock and releases the lock", async () => {
  const k = key();
  const run = (async () => {
    await wg.addPeer(k, "10.66.0.230");
    await wg.removePeer(k);
    await wg.addPeer(k, "10.66.0.230");
    await wg.removePeer(k);
  })();
  const timeout = new Promise((_, rej) => setTimeout(() => rej(new Error("deadlock")), 5_000).unref());
  await Promise.race([run, timeout]);
  assert.strictEqual(confLock.locked, false);
  assert.strictEqual(confLock.queueLength, 0);
});

test("peers - atomic write leaves no temp file and keeps mode 0600", async () => {
  await wg.addPeer(key(), "10.66.0.240");
  assert.ok(!fs.existsSync(`${CONF}.tmp`));
  assert.strictEqual(fs.statSync(CONF).mode & 0o777, 0o600);
});
